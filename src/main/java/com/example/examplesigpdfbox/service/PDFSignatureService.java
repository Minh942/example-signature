package com.example.examplesigpdfbox.service;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

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
                contentStream.setStrokingColor(156 / 255f, 39 / 255f, 176 / 255f);
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
                    contentStream.setStrokingColor(255 / 255f, 0 / 255f, 0 / 255f);
                    contentStream.setLineWidth(2);
                    contentStream.addRect(x - 5, y - 5, width + 10, height + 10);
                    contentStream.stroke();
                    break;
                case "seal":
                    // Add blue circular border for seal style
                    contentStream.setStrokingColor(0 / 255f, 0 / 255f, 255 / 255f);
                    contentStream.setLineWidth(2);
                    float centerX = x + width / 2;
                    float centerY = y + height / 2;
                    float radius = Math.max(width, height) / 2 + 5;
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
                    contentStream.setStrokingColor(255 / 255f, 0 / 255f, 0 / 255f);
                    contentStream.setLineWidth(2);
                    contentStream.addRect(x - 5, y - 5, width + 10, height + 10);
                    contentStream.stroke();
                    break;
                case "seal":
                    // Add blue circular border for seal style
                    contentStream.setStrokingColor(0 / 255f, 0 / 255f, 255 / 255f);
                    contentStream.setLineWidth(2);
                    float centerX = x + width / 2;
                    float centerY = y + height / 2;
                    float radius = Math.max(width, height) / 2 + 5;
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

            // Convert the padded signature byte array to a hexadecimal string
            StringBuilder hexSignature = new StringBuilder();
            for (byte b : paddedSignature) {
                hexSignature.append(String.format("%02x", b));
            }

            // Update the Contents field with the actual signature data as a hexadecimal string
            signatureDict.setItem(COSName.CONTENTS, new COSString("<" + hexSignature + ">"));

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
        int reservedSpace = 25000000; // Reserve 25MB for the signature
        signatureOptions.setPreferredSignatureSize(reservedSpace);
        signatureOptions.setPage(0);

        // Create a temporary signature to get the hash and reserve space
        document.addSignature(signature, content -> {
            // Read the content to calculate the hash
            byte[] contentBytes = content.readAllBytes();
            // Note: We don't return the hash here. We return the placeholder.
            // The hash is calculated based on the content *before* the placeholder is filled.

            // Return a byte array of the desired reserved size (e.g., 25MB)
            // This forces PDFBox to reserve this amount of space for the Contents field.
            // Use the same reservedSpace
            // Fill with zeros (ByteArrayOutputStream already initializes with zeros)
            return new byte[reservedSpace];
        }, signatureOptions);

        // Save to temporary file. This creates the placeholder.
        File tempFile = File.createTempFile("temp", ".pdf");
        document.saveIncremental(new FileOutputStream(tempFile));
        document.close();

        // Re-open the document to calculate the hash correctly based on the document *with* the placeholder
        PDDocument docForHash = Loader.loadPDF(tempFile);
        // Get the signature dictionary to calculate the hash using getByteRange
        PDSignature sigForHash = docForHash.getSignatureDictionaries().get(0);
        ByteArrayOutputStream hashOutputStream = new ByteArrayOutputStream();

        // Calculate the hash based on the byte range *excluding* the placeholder
        byte[] buffer = new byte[4096];
        RandomAccessRead randAccess = new RandomAccessReadBuffer(Files.readAllBytes(tempFile.toPath()));
        COSArray byteRange = (COSArray) sigForHash.getCOSObject().getDictionaryObject(COSName.BYTERANGE);

        long initialPartOffset = ((org.apache.pdfbox.cos.COSInteger) byteRange.get(0)).longValue();
        long initialPartLength = ((org.apache.pdfbox.cos.COSInteger) byteRange.get(1)).longValue();
        long finalPartOffset = ((org.apache.pdfbox.cos.COSInteger) byteRange.get(2)).longValue();
        long finalPartLength = ((org.apache.pdfbox.cos.COSInteger) byteRange.get(3)).longValue();

        // Read the initial part
        randAccess.seek(initialPartOffset);
        long remainingInitial = initialPartLength;
        while (remainingInitial > 0) {
            int bytesToRead = (int) Math.min(buffer.length, remainingInitial);
            int bytesRead = randAccess.read(buffer, 0, bytesToRead);
            if (bytesRead == -1) break; // Should not happen in this case
            hashOutputStream.write(buffer, 0, bytesRead);
            remainingInitial -= bytesRead;
        }

        // Read the final part
        randAccess.seek(finalPartOffset);
        long remainingFinal = finalPartLength;
        while (remainingFinal > 0) {
            int bytesToRead = (int) Math.min(buffer.length, remainingFinal);
            int bytesRead = randAccess.read(buffer, 0, bytesToRead);
            if (bytesRead == -1) break; // Should not happen in this case
            hashOutputStream.write(buffer, 0, bytesRead);
            remainingFinal -= bytesRead;
        }

        randAccess.close();
        docForHash.close();

        byte[] hash = hashOutputStream.toByteArray();

        return new HashCreationResult(hash, tempFile.getAbsolutePath());
    }

    /**
     * Helper class to return hash and temporary file path
     */
    public record HashCreationResult(byte[] hash, String tempFilePath) {

    }

    /**
     * Signs the hash using .p12 file
     */
    public byte[] signHashWithP12(byte[] hash, String p12Path, String p12Password) throws Exception {
        // Load the keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(p12Path), p12Password.toCharArray());

        // Get the private key and certificate
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, p12Password.toCharArray());
        Certificate[] certChain = keyStore.getCertificateChain(alias);

        // Create the signature
        List<X509Certificate> certList = new ArrayList<>();
        for (Certificate cert : certChain) {
            certList.add((X509Certificate) cert);
        }
        JcaCertStore certStore = new JcaCertStore(certList);

        // Create the signature generator
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        // Add certificates to the generator
        generator.addCertificates(certStore);

        // Create ContentSigner
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(privateKey);

        // Create SignerInfoGeneratorBuilder
        JcaDigestCalculatorProviderBuilder dcpBuilder = new JcaDigestCalculatorProviderBuilder();
        DigestCalculatorProvider digestProvider = dcpBuilder.build();

        // Create signed attributes table
        Hashtable<ASN1ObjectIdentifier, Attribute> signedAttrs = new Hashtable<>();

        // Add contentType attribute (required for PDF)
        signedAttrs.put(CMSAttributes.contentType, new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)));

        // Add signingTime attribute
        signedAttrs.put(CMSAttributes.signingTime, new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))));

        // Add messageDigest attribute
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashOfHash = sha256.digest(hash);
        signedAttrs.put(CMSAttributes.messageDigest, new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hashOfHash))));

        // Create AttributeTable from attributes
        AttributeTable signedAttributeTable = new AttributeTable(signedAttrs);

        // Create SignerInfoGenerator
        X509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) certChain[0]);
        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestProvider)
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(signedAttributeTable))
                .build(contentSigner, certHolder);

        // Add SignerInfoGenerator to the generator
        generator.addSignerInfoGenerator(signerInfoGenerator);

        // Create the signature
        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(hash);
        CMSSignedData signedData = generator.generate(cmsData, false); // Use false for detached signature

        return signedData.getEncoded();
    }

    /**
     * Bước 1: Chuẩn bị tài liệu và tạo chữ ký
     */
    public ExternalSigningSupport prepareDocumentForSigning(String inputPath, String outputPath) throws IOException {
        try (PDDocument document = Loader.loadPDF(new File(inputPath))) {
            // Tạo đối tượng chữ ký
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Digital Signature");
            signature.setReason("Document Signing");
            signature.setLocation("Company Location");

            // Thiết lập thời gian ký
            Calendar cal = Calendar.getInstance();
            signature.setSignDate(cal);

            // Thêm chữ ký vào tài liệu
            SignatureOptions options = new SignatureOptions();
            document.addSignature(signature, null, options);
            document.setDocumentId(System.currentTimeMillis());

            // Lưu tài liệu và chuẩn bị cho việc ký
            return document.saveIncrementalForExternalSigning(new FileOutputStream(outputPath));
        }
    }

    /**
     * Bước 2: Tạo hash và ký số
     */
    public byte[] createSignature(ExternalSigningSupport externalSigning) throws IOException {
        try {
            // Đọc nội dung cần ký
            byte[] content = externalSigning.getContent().readAllBytes();

            // Tạo hash SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(content);
            String base64Hash = Base64.getEncoder().encodeToString(hashBytes);

            // Ký hash
            byte[] signedHash = signHash(base64Hash);

            // Tạo CMS signature
            return createCMSSignature(signedHash);
        } catch (Exception e) {
            throw new IOException("Error creating signature", e);
        }
    }

    /**
     * Bước 3: Hoàn tất việc ký và lưu tài liệu
     */
    public void completeSigning(ExternalSigningSupport externalSigning, byte[] signature) throws IOException {
        try {
            // Thêm chữ ký vào tài liệu
            externalSigning.setSignature(signature);
        } catch (Exception e) {
            throw new IOException("Error completing signature", e);
        }
    }

    /**
     * Tạo chữ ký CMS
     */
    private byte[] createCMSSignature(byte[] signedHash) throws Exception {
        ContentSigner nonSigner = new ContentSigner() {
            @Override
            public byte[] getSignature() {
                return signedHash;
            }

            @Override
            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream();
            }

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSA");
            }
        };

        List<X509Certificate> certChain = loadCertificateChain();
        X509Certificate cert = certChain.get(0);
        org.bouncycastle.asn1.x509.Certificate bouncycastleCert = org.bouncycastle.asn1.x509.Certificate
                .getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider);
        sigb.setDirectSignature(true);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addCertificates(new JcaCertStore(certChain));
        SignerInfoGenerator signerInfoGenerator = sigb.build(nonSigner, new X509CertificateHolder(bouncycastleCert));
        gen.addSignerInfoGenerator(signerInfoGenerator);

        CMSTypedData msg = new CMSProcessableInputStream(new ByteArrayInputStream("not used".getBytes()));
        CMSSignedData signedData = gen.generate(msg, false);
        return signedData.getEncoded();
    }

    /**
     * Ký hash với private key
     */
    private byte[] signHash(String hash) throws Exception {
        byte[] hashBytes = Base64.getDecoder().decode(hash);
        Signature sig = Signature.getInstance("NONEwithRSA");
        sig.initSign(loadPrivateKey());
        byte[] hashWrapped = wrapForRsaSign(hashBytes);
        sig.update(hashWrapped);
        return sig.sign();
    }

    /**
     * Load chuỗi chứng chỉ
     */
    private List<X509Certificate> loadCertificateChain() throws Exception {
        String certPath = ""; // Cấu hình đường dẫn file chứng chỉ
        try (InputStream inStream = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (List<X509Certificate>) cf.generateCertificates(inStream);
        }
    }

    /**
     * Load private key
     */
    private PrivateKey loadPrivateKey() throws Exception {
        String privateKeyPath = ""; // Cấu hình đường dẫn file private key
        try (Reader reader = new FileReader(privateKeyPath, StandardCharsets.UTF_8);
             PemReader pemReader = new PemReader(reader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] keyBytes = pemObject.getContent();
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(keyBytes);
            return kf.generatePrivate(privSpec);
        }
    }

    /**
     * Wrap hash cho việc ký RSA
     */
    private byte[] wrapForRsaSign(byte[] dig) throws IOException {
        ASN1ObjectIdentifier oid = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256").getAlgorithm();

        ASN1EncodableVector algIdentifier = new ASN1EncodableVector();
        algIdentifier.add(oid);
        algIdentifier.add(DERNull.INSTANCE);

        ASN1EncodableVector digestInfo = new ASN1EncodableVector();
        digestInfo.add(new DERSequence(algIdentifier));
        digestInfo.add(new DEROctetString(dig));

        return new DERSequence(digestInfo).getEncoded();
    }
}