package com.example.examplesigpdfbox.service;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;

@Service
public class PDFSignatureService {

    public void signPDFWithDetachedSignature(
            String inputPDFPath,
            String outputPDFPath,
            String signatureImagePath,
            String p12Path,
            String p12Password,
            float x,
            float y,
            float width,
            float height,
            String signatureStyle) throws Exception {
        
        // Load the PDF document
        PDDocument document = Loader.loadPDF(new File(inputPDFPath));
        
        // Add signature image to the first page
        PDPage page = document.getPage(0);
        PDImageXObject signatureImage = PDImageXObject.createFromFile(signatureImagePath, document);
        
        // Create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Example Signer");
        signature.setLocation("Example Location");
        signature.setReason("Example Reason");
        signature.setSignDate(Calendar.getInstance());
        
        // Create signature options with larger size
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPage(0); // Sign on first page
        signatureOptions.setPreferredSignatureSize(5000000); // 5MB for signature space

        // Handle deferred signature
        if ("deferred".equals(signatureStyle)) {
            // For deferred signature, we'll create a placeholder signature
            // that can be signed later
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Chờ ký");
            signature.setLocation("Chờ ký");
            signature.setReason("Chờ ký");
            signature.setSignDate(Calendar.getInstance());
            
            // Create a placeholder signature that can be signed later
            document.addSignature(signature, new SignatureInterface() {
                @Override
                public byte[] sign(InputStream content) {
                    // Create a dummy signature with minimal size
                    // 1KB dummy signature
                    return new byte[999999];
                }
            }, signatureOptions);

            // Add signature image at the specified location with style
            try (PDPageContentStream contentStream = new PDPageContentStream(
                    document, page, PDPageContentStream.AppendMode.APPEND, true, true)) {
                
                // Add purple border for deferred style
                contentStream.setStrokingColor(156/255f, 39/255f, 176/255f);
                contentStream.setLineWidth(2);
                contentStream.addRect(x - 5, y - 5, width + 10, height + 10);
                contentStream.stroke();
                
                // Draw the signature image
                contentStream.drawImage(signatureImage, x, y, width, height);
            }

            // Save the PDF with the empty signature
            document.saveIncremental(new FileOutputStream(outputPDFPath));
            document.close();
            return;
        }

        // Load the keystore
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(p12Path), p12Password.toCharArray());

        // Get the private key and certificate
        String alias = keyStore.aliases().nextElement();
        java.security.PrivateKey privateKey = (java.security.PrivateKey) keyStore.getKey(alias, p12Password.toCharArray());
        java.security.cert.Certificate[] certChain = keyStore.getCertificateChain(alias);

        // Create the signature
        List<java.security.cert.X509Certificate> certList = new ArrayList<>();
        for (java.security.cert.Certificate cert : certChain) {
            certList.add((java.security.cert.X509Certificate) cert);
        }
        JcaCertStore certStore = new JcaCertStore(certList);

        // Create the signature generator with SHA-256
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(privateKey);
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().build())
                        .build(contentSigner, (java.security.cert.X509Certificate) certChain[0]));
        generator.addCertificates(certStore);

        // Add signature to document
        document.addSignature(signature, content -> {
            try {
                // Read the content
                byte[] contentBytes = content.readAllBytes();

                // Create the signature
                CMSProcessableByteArray cmsData = new CMSProcessableByteArray(contentBytes);
                CMSSignedData signedData = generator.generate(cmsData, true);

                return signedData.getEncoded();
            } catch (Exception e) {
                throw new IOException(e);
            }
        }, signatureOptions);

        // Add signature image at the specified location with style
        try (PDPageContentStream contentStream = new PDPageContentStream(
                document, page, PDPageContentStream.AppendMode.APPEND, true, true)) {
            
            // Apply different styles based on signatureStyle
            switch (signatureStyle) {
                case "stamp":
                    // Add red border for stamp style
                    contentStream.setStrokingColor(255/255f, 0/255f, 0/255f);
                    contentStream.setLineWidth(2);
                    contentStream.addRect(x - 5, y - 5, width + 10, height + 10);
                    contentStream.stroke();
                    break;
                case "seal":
                    // Add blue circular border for seal style
                    contentStream.setStrokingColor(0/255f, 0/255f, 255/255f);
                    contentStream.setLineWidth(2);
                    float centerX = x + width/2;
                    float centerY = y + height/2;
                    float radius = Math.max(width, height)/2 + 5;
                    contentStream.moveTo(centerX + radius, centerY);
                    contentStream.curveTo(
                        centerX + radius, centerY + radius * 0.552f,
                        centerX + radius * 0.552f, centerY + radius,
                        centerX, centerY + radius
                    );
                    contentStream.curveTo(
                        centerX - radius * 0.552f, centerY + radius,
                        centerX - radius, centerY + radius * 0.552f,
                        centerX - radius, centerY
                    );
                    contentStream.curveTo(
                        centerX - radius, centerY - radius * 0.552f,
                        centerX - radius * 0.552f, centerY - radius,
                        centerX, centerY - radius
                    );
                    contentStream.curveTo(
                        centerX + radius * 0.552f, centerY - radius,
                        centerX + radius, centerY - radius * 0.552f,
                        centerX + radius, centerY
                    );
                    contentStream.stroke();
                    break;
            }
            
            // Draw the signature image
            contentStream.drawImage(signatureImage, x, y, width, height);
        }

        // Save the PDF with the signature
        document.saveIncremental(new FileOutputStream(outputPDFPath));
        document.close();
    }

    public void embedSignatureImage(
            String inputPDFPath,
            String outputPDFPath,
            String signatureImagePath,
            float x,
            float y,
            float width,
            float height,
            String signatureStyle) throws IOException {
        
        // Load the PDF document
        PDDocument document = Loader.loadPDF(new File(inputPDFPath));
        
        // Add signature image to the first page
        PDPage page = document.getPage(0);
        PDImageXObject signatureImage = PDImageXObject.createFromFile(signatureImagePath, document);
        
        // Add signature image at the specified location with style
        try (PDPageContentStream contentStream = new PDPageContentStream(
                document, page, PDPageContentStream.AppendMode.APPEND, true, true)) {
            
            // Apply different styles based on signatureStyle
            switch (signatureStyle) {
                case "stamp":
                    // Add red border for stamp style
                    contentStream.setStrokingColor(255/255f, 0/255f, 0/255f);
                    contentStream.setLineWidth(2);
                    contentStream.addRect(x - 5, y - 5, width + 10, height + 10);
                    contentStream.stroke();
                    break;
                case "seal":
                    // Add blue circular border for seal style
                    contentStream.setStrokingColor(0/255f, 0/255f, 255/255f);
                    contentStream.setLineWidth(2);
                    float centerX = x + width/2;
                    float centerY = y + height/2;
                    float radius = Math.max(width, height)/2 + 5;
                    contentStream.moveTo(centerX + radius, centerY);
                    contentStream.curveTo(
                        centerX + radius, centerY + radius * 0.552f,
                        centerX + radius * 0.552f, centerY + radius,
                        centerX, centerY + radius
                    );
                    contentStream.curveTo(
                        centerX - radius * 0.552f, centerY + radius,
                        centerX - radius, centerY + radius * 0.552f,
                        centerX - radius, centerY
                    );
                    contentStream.curveTo(
                        centerX - radius, centerY - radius * 0.552f,
                        centerX - radius * 0.552f, centerY - radius,
                        centerX, centerY - radius
                    );
                    contentStream.curveTo(
                        centerX + radius * 0.552f, centerY - radius,
                        centerX + radius, centerY - radius * 0.552f,
                        centerX + radius, centerY
                    );
                    contentStream.stroke();
                    break;
            }
            
            // Draw the signature image
            contentStream.drawImage(signatureImage, x, y, width, height);
        }

        // Save the PDF with the signature image
        document.save(new FileOutputStream(outputPDFPath));
        document.close();
    }

    public void signDeferredSignature(
            String inputPDFPath,
            String outputPDFPath,
            String p12Path,
            String p12Password) throws Exception {
        
        // Load the PDF document
        PDDocument document = Loader.loadPDF(new File(inputPDFPath));
        
        // Get the existing signature
        PDSignature signature = document.getSignatureDictionaries().get(0);
        
        // Create signature options with larger size
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(5000000); // 5MB for signature space
        signatureOptions.setPage(0); // Sign on first page
        
        // Load the keystore
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(p12Path), p12Password.toCharArray());

        // Get the private key and certificate
        String alias = keyStore.aliases().nextElement();
        java.security.PrivateKey privateKey = (java.security.PrivateKey) keyStore.getKey(alias, p12Password.toCharArray());
        java.security.cert.Certificate[] certChain = keyStore.getCertificateChain(alias);

        // Create the signature
        List<java.security.cert.X509Certificate> certList = new ArrayList<>();
        for (java.security.cert.Certificate cert : certChain) {
            certList.add((java.security.cert.X509Certificate) cert);
        }
        JcaCertStore certStore = new JcaCertStore(certList);

        // Create the signature generator with SHA-256
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(privateKey);
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().build())
                        .build(contentSigner, (java.security.cert.X509Certificate) certChain[0]));
        generator.addCertificates(certStore);

        // Sign the document
        document.addSignature(signature, content -> {
            try {
                // Read the content
                byte[] contentBytes = content.readAllBytes();

                // Create the signature
                CMSProcessableByteArray cmsData = new CMSProcessableByteArray(contentBytes);
                CMSSignedData signedData = generator.generate(cmsData, true);

                return signedData.getEncoded();
            } catch (Exception e) {
                throw new IOException(e);
            }
        }, signatureOptions);

        // Save the signed PDF
        document.saveIncremental(new FileOutputStream(outputPDFPath));
        document.close();
    }

    /**
     * Embeds the signature into the PDF
     */
    public void embedSignature(String tempPDFPath, String outputPDFPath, byte[] signature) throws Exception {
        File tempFile = new File(tempPDFPath);
        if (!tempFile.exists()) {
            throw new IOException("Temporary PDF file not found.");
        }

        try (PDDocument document = Loader.loadPDF(tempFile)) {
            // Get the existing signature field dictionary
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                throw new IOException("No signature field found in the temporary PDF.");
            }
            // Assuming only one signature field is created in step 1
            PDSignature pdSignature = signatures.get(0);
            COSDictionary signatureDict = pdSignature.getCOSObject();

            // Find the ByteRange array and the Contents placeholder
            COSArray byteRange = (COSArray) signatureDict.getDictionaryObject(COSName.BYTERANGE);
            if (byteRange == null || byteRange.size() != 4) {
                throw new IOException("ByteRange not found or invalid in signature dictionary");
            }

            COSString contents = (COSString) signatureDict.getDictionaryObject(COSName.CONTENTS);
            if (contents == null) {
                throw new IOException("Contents field not found in signature dictionary");
            }

            // Ensure the signature data fits within the reserved space
            int reservedSpace = contents.getBytes().length;
            if (signature.length > reservedSpace) {
                 throw new IOException("Signature data is too large for the reserved space. Reserved: " + reservedSpace + ", Actual: " + signature.length);
            }
            
            // Update the Contents field with the actual signature data, padded with zeros if necessary
            byte[] paddedSignature = new byte[reservedSpace];
            System.arraycopy(signature, 0, paddedSignature, 0, signature.length);
            // The rest of paddedSignature is already filled with zeros
            signatureDict.setItem(COSName.CONTENTS, new COSString(paddedSignature));

            // Save the modified document incrementally
            document.saveIncremental(new FileOutputStream(outputPDFPath));
        }
        
        // Delete the temporary file after signing
        if (tempFile.exists()) {
            tempFile.delete();
        }
    }

    /**
     * Creates a hash of the PDF document for signing with .p12
     * Returns the hash and the path to the temporary PDF with signature field.
     */
    public HashCreationResult createHashForSigning(String inputPDFPath) throws IOException {
        PDDocument document = Loader.loadPDF(new File(inputPDFPath));
        
        // Create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Signer");
        signature.setLocation("Location");
        signature.setReason("Signing");
        signature.setSignDate(Calendar.getInstance());

        // Create signature options with larger size
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(10000000); // Increase to 10MB
        signatureOptions.setPage(0);

        // Create a temporary signature to get the hash
        document.addSignature(signature, new SignatureInterface() {
            @Override
            public byte[] sign(InputStream content) throws IOException {
                // Return the hash of the content
                return content.readAllBytes();
            }
        }, signatureOptions);

        // Save to temporary file to get the hash
        File tempFile = File.createTempFile("temp", ".pdf");
        document.saveIncremental(new FileOutputStream(tempFile));
        document.close();

        // Read the hash from the temporary file
        byte[] hash = Files.readAllBytes(tempFile.toPath());
        // Keep the temporary file for step 3

        return new HashCreationResult(hash, tempFile.getAbsolutePath());
    }

    /**
     * Helper class to return hash and temporary file path
     */
    public static class HashCreationResult {
        private final byte[] hash;
        private final String tempFilePath;

        public HashCreationResult(byte[] hash, String tempFilePath) {
            this.hash = hash;
            this.tempFilePath = tempFilePath;
        }

        public byte[] getHash() {
            return hash;
        }

        public String getTempFilePath() {
            return tempFilePath;
        }
    }

    /**
     * Signs the hash using .p12 file
     */
    public byte[] signHashWithP12(byte[] hash, String p12Path, String p12Password) throws Exception {
        // Load the keystore
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(p12Path), p12Password.toCharArray());

        // Get the private key and certificate
        String alias = keyStore.aliases().nextElement();
        java.security.PrivateKey privateKey = (java.security.PrivateKey) keyStore.getKey(alias, p12Password.toCharArray());
        java.security.cert.Certificate[] certChain = keyStore.getCertificateChain(alias);

        // Create the signature
        List<java.security.cert.X509Certificate> certList = new ArrayList<>();
        for (java.security.cert.Certificate cert : certChain) {
            certList.add((java.security.cert.X509Certificate) cert);
        }
        JcaCertStore certStore = new JcaCertStore(certList);

        // Create the signature generator with SHA-256
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(privateKey);
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().build())
                        .build(contentSigner, (java.security.cert.X509Certificate) certChain[0]));
        generator.addCertificates(certStore);

        // Create the signature
        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(hash);
        CMSSignedData signedData = generator.generate(cmsData, true);

        return signedData.getEncoded();
    }

    /**
     * Example of how to use two-step signing with .p12
     */
    public void signWithP12Example(String inputPDFPath, String outputPDFPath, String p12Path, String p12Password) throws Exception {
        // Step 1: Create hash for signing
        HashCreationResult hashResult = createHashForSigning(inputPDFPath);

        // Step 2: Sign the hash with .p12
        byte[] signature = signHashWithP12(hashResult.getHash(), p12Path, p12Password);

        // Step 3: Embed the signature
        embedSignature(hashResult.getTempFilePath(), outputPDFPath, signature);
    }
} 