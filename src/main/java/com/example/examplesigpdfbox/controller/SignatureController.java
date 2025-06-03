package com.example.examplesigpdfbox.controller;

import com.example.examplesigpdfbox.service.PDFSignatureService;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/api/signature")
public class SignatureController {

    @Autowired
    private PDFSignatureService pdfSignatureService;

    @GetMapping("/test")
    public String testPage() {
        return "signature-test";
    }

    // Three-Step Signing APIs
    @PostMapping("/step1/prepare")
    @ResponseBody
    public Map<String, String> prepareDocument(@RequestParam("file") MultipartFile file) throws IOException {
        try {
            // Create temporary directory and files
            Path tempDir = Files.createTempDirectory("pdf_signature_");
            File inputPDF = new File(tempDir.toFile(), "input.pdf");
            File outputPDF = new File(tempDir.toFile(), "output.pdf");
            
            // Save uploaded file using buffered streams
            try (InputStream inputStream = file.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(inputPDF)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
            
            // Load the PDF document
            try (PDDocument document = Loader.loadPDF(inputPDF)) {
                // Create signature dictionary
                PDSignature signature = new PDSignature();
                signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
                signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
                signature.setName("Example User");
                signature.setReason("Testing");
                signature.setLocation("Test Location");
                signature.setSignDate(Calendar.getInstance());

                // Add signature to document
                SignatureOptions options = new SignatureOptions();
                document.addSignature(signature, null, options);

                // Save document for external signing using buffered streams
                try (FileOutputStream outputStream = new FileOutputStream(outputPDF)) {
                    document.saveIncremental(outputStream);
                }

                // Get the content to sign using buffered reading
                byte[] content;
                try (FileInputStream fis = new FileInputStream(outputPDF)) {
                    content = fis.readAllBytes();
                }
                String hash = Base64.getEncoder().encodeToString(content);
                
                Map<String, String> result = new HashMap<>();
                result.put("hash", hash);
                result.put("tempFilePath", outputPDF.getAbsolutePath());
                return result;
            }
        } catch (Exception e) {
            throw new IOException("Error preparing document: " + e.getMessage(), e);
        }
    }

    @PostMapping("/step2/sign")
    @ResponseBody
    public Map<String, String> signHash(
            @RequestParam("hash") String hash,
            @RequestParam("p12File") MultipartFile p12File,
            @RequestParam("password") String password) throws IOException {
        try {
            // Create temporary directory and file
            Path tempDir = Files.createTempDirectory("pdf_signature_");
            File p12 = new File(tempDir.toFile(), "certificate.p12");
            
            // Save uploaded file using buffered streams
            try (InputStream inputStream = p12File.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(p12)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
            
            // Convert hash back to bytes
            byte[] hashBytes = Base64.getDecoder().decode(hash);
            
            // Sign hash with P12
            byte[] signature = pdfSignatureService.signHashWithP12(hashBytes, p12.getAbsolutePath(), password);
            
            Map<String, String> result = new HashMap<>();
            result.put("signature", Base64.getEncoder().encodeToString(signature));
            return result;
        } catch (Exception e) {
            throw new IOException("Error signing hash: " + e.getMessage(), e);
        }
    }

    @PostMapping("/step3/complete")
    public ResponseEntity<Resource> completeSigning(
            @RequestParam("tempFilePath") String tempFilePath,
            @RequestParam("signature") String signature) throws IOException {
        try {
            // Create temporary directory for output
            Path tempDir = Files.createTempDirectory("pdf_signature_");
            File outputPDF = new File(tempDir.toFile(), "signed.pdf");
            
            // Convert signature back to bytes
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            
            // Load the temporary PDF
            try (PDDocument document = Loader.loadPDF(new File(tempFilePath))) {
                // Get the first signature
                PDSignature pdSignature = document.getSignatureDictionaries().get(0);
                
                // Set the signature value
                pdSignature.setContents(signatureBytes);
                
                // Save the signed PDF using buffered streams
                try (FileOutputStream outputStream = new FileOutputStream(outputPDF)) {
                    document.saveIncremental(outputStream);
                }
            }
            
            // Return the signed PDF file using FileSystemResource for streaming
            Resource signedPdf = new FileSystemResource(outputPDF);
            
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed_document.pdf\"")
                    .body(signedPdf);
        } catch (Exception e) {
            throw new IOException("Error completing signature: " + e.getMessage(), e);
        }
    }

    // Direct Signing APIs
    @PostMapping("/sign")
    public ResponseEntity<Resource> signPDF(
            @RequestParam("pdfFile") MultipartFile pdfFile,
            @RequestParam("signatureImage") MultipartFile signatureImage,
            @RequestParam("p12File") MultipartFile p12File,
            @RequestParam("p12Password") String p12Password,
            @RequestParam("x") float x,
            @RequestParam("y") float y,
            @RequestParam("width") float width,
            @RequestParam("height") float height,
            @RequestParam(value = "signatureStyle", defaultValue = "normal") String signatureStyle) throws IOException {
        try {
            // Create temporary directory
            Path tempDir = Files.createTempDirectory("pdf_signature_");

            // Create temporary files
            File inputPDF = new File(tempDir.toFile(), "input.pdf");
            File outputPDF = new File(tempDir.toFile(), "output.pdf");
            File sigImage = new File(tempDir.toFile(), "signature.png");
            File p12 = new File(tempDir.toFile(), "certificate.p12");

            // Save uploaded files
            Files.copy(pdfFile.getInputStream(), inputPDF.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(signatureImage.getInputStream(), sigImage.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(p12File.getInputStream(), p12.toPath(), StandardCopyOption.REPLACE_EXISTING);

            // Sign the PDF
            pdfSignatureService.signPDFWithDetachedSignature(
                    inputPDF.getAbsolutePath(),
                    outputPDF.getAbsolutePath(),
                    sigImage.getAbsolutePath(),
                    p12.getAbsolutePath(),
                    p12Password,
                    x, y, width, height,
                    signatureStyle
            );

            // Return the signed PDF file
            Resource signedPdf = new ByteArrayResource(Files.readAllBytes(outputPDF.toPath()));
            
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed_document.pdf\"")
                    .body(signedPdf);
        } catch (Exception e) {
            throw new IOException("Error signing PDF: " + e.getMessage(), e);
        }
    }

    @PostMapping("/embed-image")
    public ResponseEntity<Resource> embedSignatureImage(
            @RequestParam("pdfFile") MultipartFile pdfFile,
            @RequestParam("signatureImage") MultipartFile signatureImage,
            @RequestParam("x") float x,
            @RequestParam("y") float y,
            @RequestParam("width") float width,
            @RequestParam("height") float height,
            @RequestParam(value = "signatureStyle", defaultValue = "normal") String signatureStyle) throws IOException {
        try {
            // Create temporary files
            Path tempDir = Files.createTempDirectory("pdf_signature_");
            File inputPDF = new File(tempDir.toFile(), "input.pdf");
            File outputPDF = new File(tempDir.toFile(), "output.pdf");
            File sigImage = new File(tempDir.toFile(), "signature.png");

            // Save uploaded files
            Files.copy(pdfFile.getInputStream(), inputPDF.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(signatureImage.getInputStream(), sigImage.toPath(), StandardCopyOption.REPLACE_EXISTING);

            // Embed the signature image
            pdfSignatureService.embedSignatureImage(
                    inputPDF.getAbsolutePath(),
                    outputPDF.getAbsolutePath(),
                    sigImage.getAbsolutePath(),
                    x, y, width, height,
                    signatureStyle
            );

            // Return the PDF file with embedded image
            Resource signedPdf = new ByteArrayResource(Files.readAllBytes(outputPDF.toPath()));
            
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed_document.pdf\"")
                    .body(signedPdf);
        } catch (Exception e) {
            throw new IOException("Error embedding signature image: " + e.getMessage(), e);
        }
    }

    @PostMapping("/sign-deferred")
    public ResponseEntity<Resource> signDeferredSignature(
            @RequestParam("pdfFile") MultipartFile pdfFile,
            @RequestParam("p12File") MultipartFile p12File,
            @RequestParam("p12Password") String p12Password) throws IOException {
        try {
            // Create temporary directory
            Path tempDir = Files.createTempDirectory("pdf_signature_");

            // Create temporary files
            File inputPDF = new File(tempDir.toFile(), "input.pdf");
            File outputPDF = new File(tempDir.toFile(), "output.pdf");
            File p12 = new File(tempDir.toFile(), "certificate.p12");

            // Save uploaded files
            Files.copy(pdfFile.getInputStream(), inputPDF.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(p12File.getInputStream(), p12.toPath(), StandardCopyOption.REPLACE_EXISTING);

            // Sign the deferred signature
            pdfSignatureService.signDeferredSignature(
                    inputPDF.getAbsolutePath(),
                    outputPDF.getAbsolutePath(),
                    p12.getAbsolutePath(),
                    p12Password
            );

            // Return the signed PDF file
            Resource signedPdf = new ByteArrayResource(Files.readAllBytes(outputPDF.toPath()));
            
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed_document.pdf\"")
                    .body(signedPdf);
        } catch (Exception e) {
            throw new IOException("Error signing deferred signature: " + e.getMessage(), e);
        }
    }
} 