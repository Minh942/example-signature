package com.example.examplesigpdfbox.controller;

import com.example.examplesigpdfbox.service.PDFSignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/api/signature")
public class SignatureController {

    @Autowired
    private PDFSignatureService pdfSignatureService;

    @PostMapping("/sign")
    public ResponseEntity<?> signPDF(
            @RequestParam("pdfFile") MultipartFile pdfFile,
            @RequestParam("signatureImage") MultipartFile signatureImage,
            @RequestParam("p12File") MultipartFile p12File,
            @RequestParam("p12Password") String p12Password,
            @RequestParam("x") float x,
            @RequestParam("y") float y,
            @RequestParam("width") float width,
            @RequestParam("height") float height,
            @RequestParam(value = "signatureStyle", defaultValue = "normal") String signatureStyle) {
        try {
            // Create temporary files
            Path tempDir = Files.createTempDirectory("pdf_signature_");
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
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed.pdf");
            headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(new FileSystemResource(outputPDF));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error signing PDF: " + e.getMessage());
        }
    }

    @PostMapping("/embed-image")
    public ResponseEntity<?> embedSignatureImage(
            @RequestParam("pdfFile") MultipartFile pdfFile,
            @RequestParam("signatureImage") MultipartFile signatureImage,
            @RequestParam("x") float x,
            @RequestParam("y") float y,
            @RequestParam("width") float width,
            @RequestParam("height") float height,
            @RequestParam(value = "signatureStyle", defaultValue = "normal") String signatureStyle) {
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
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed.pdf");
            headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(new FileSystemResource(outputPDF));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error embedding signature image: " + e.getMessage());
        }
    }

    @PostMapping("/sign-deferred")
    public ResponseEntity<?> signDeferredSignature(
            @RequestParam("pdfFile") MultipartFile pdfFile,
            @RequestParam("p12File") MultipartFile p12File,
            @RequestParam("p12Password") String p12Password) {
        try {
            // Create temporary files
            Path tempDir = Files.createTempDirectory("pdf_signature_");
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
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed.pdf");
            headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(new FileSystemResource(outputPDF));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error signing deferred signature: " + e.getMessage());
        }
    }

    @GetMapping("/test")
    public String testPage() {
        return "signature-test";
    }

    @PostMapping("/step1/create-hash")
    @ResponseBody
    public ResponseEntity<?> createHash(@RequestParam("file") MultipartFile file) {
        try {
            // Save uploaded file temporarily
            File tempFile = File.createTempFile("temp", ".pdf");
            file.transferTo(tempFile);

            // Create hash for signing and get the temporary file path
            PDFSignatureService.HashCreationResult hashResult = pdfSignatureService.createHashForSigning(tempFile.getAbsolutePath());

            // Return hash and temporary file path
            Map<String, String> response = new HashMap<>();
            response.put("hash", Base64.getEncoder().encodeToString(hashResult.hash()));
            response.put("originalFileName", file.getOriginalFilename());
            response.put("tempFilePath", hashResult.tempFilePath()); // Return temp file path

            // Do NOT delete tempFile here, it's needed for step 3

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error creating hash: " + e.getMessage());
        }
    }

    @PostMapping("/step2/sign-hash")
    @ResponseBody
    public ResponseEntity<?> signHash(
            @RequestParam("hash") String hashBase64,
            @RequestParam("p12File") MultipartFile p12File,
            @RequestParam("password") String password) {
        try {
            // Save p12 file temporarily
            File tempP12File = File.createTempFile("temp", ".p12");
            p12File.transferTo(tempP12File);

            // Decode hash
            byte[] hash = Base64.getDecoder().decode(hashBase64);

            // Sign hash
            byte[] signature = pdfSignatureService.signHashWithP12(hash, tempP12File.getAbsolutePath(), password);

            // Clean up
            tempP12File.delete();

            // Return signature as base64
            String signatureBase64 = Base64.getEncoder().encodeToString(signature);
            Map<String, String> response = new HashMap<>();
            response.put("signature", signatureBase64);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error signing hash: " + e.getMessage());
        }
    }

    @PostMapping("/step3/embed-signature")
    @ResponseBody
    public ResponseEntity<?> embedSignature(
            @RequestParam("tempFilePath") String tempFilePath, // Get temp file path
            @RequestParam("signature") String signatureBase64) {
        try {
            // Create output file
            File outputFile = File.createTempFile("signed", ".pdf");

            // Decode signature
            byte[] signature = Base64.getDecoder().decode(signatureBase64);

            // Embed signature
            pdfSignatureService.embedSignature(tempFilePath, outputFile.getAbsolutePath(), signature);

            // Read signed file
            byte[] signedPdf = Files.readAllBytes(outputFile.toPath());

            // Clean up
            outputFile.delete();

            // Return signed PDF
            ByteArrayResource resource = new ByteArrayResource(signedPdf);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed.pdf")
                    .contentType(MediaType.APPLICATION_PDF)
                    .contentLength(signedPdf.length)
                    .body(resource);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error embedding signature: " + e.getMessage());
        }
    }
} 