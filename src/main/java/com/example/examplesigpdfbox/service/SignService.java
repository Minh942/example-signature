package com.example.examplesigpdfbox.service;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Service
public class SignService {

    public void generateDigitalCertificateSign() {
        String inputPath = "";
        try (PDDocument document = Loader.loadPDF(new File(inputPath))) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//            signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            signature.setName("test");
            signature.setReason("Testing purposes");
            signature.setLocation("Test Location");


            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
            Date date = sdf.parse("20250515 00:00:00");// all done
            Calendar cal = sdf.getCalendar();
            cal.setTime(date);
            signature.setSignDate(cal);


            SignatureOptions options = new SignatureOptions();
            document.addSignature(signature, null, options);
            document.setDocumentId(1234L);
            String outputPath = "";
            ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(new FileOutputStream(outputPath));

            // invoke external signature service

            byte[] cmsSignature = signWithoutAttributes(externalSigning.getContent());

//            byte[] cmsSignature = signWithAttributes(externalSigning.getContent());
            externalSigning.setSignature(cmsSignature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public byte[] signWithoutAttributes(InputStream content) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] originalContent = content.readAllBytes();
            byte[] hashBytes = digest.digest(originalContent);
            String base64Hash = Base64.getEncoder().encodeToString(hashBytes);
            byte[] signedHash = remoteSign(base64Hash);

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

            List<X509Certificate> certChain = cerFileToCertChain();
            X509Certificate cert = certChain.get(0);
            org.bouncycastle.asn1.x509.Certificate bouncycastleCert = org.bouncycastle.asn1.x509.Certificate
                    .getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
            JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider);

            // No attributes
            sigb.setDirectSignature(true);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new JcaCertStore(certChain));
            SignerInfoGenerator signerInfoGenerator = sigb.build(nonSigner, new X509CertificateHolder(bouncycastleCert));
            gen.addSignerInfoGenerator(signerInfoGenerator);

            // Not used
            CMSTypedData msg = new CMSProcessableInputStream(new ByteArrayInputStream("not used".getBytes()));
            CMSSignedData signedData = gen.generate(msg, false);
            return signedData.getEncoded();

        } catch (Exception e) {
            throw new IOException(e);
        }
    }


    public byte[] signWithAttributes(InputStream content) throws IOException {
        // cannot be done private (interface)
        try {
            ContentSigner contentSigner = new ContentSigner() {
                private final MessageDigest digest = MessageDigest.getInstance("SHA-256");
                private final ByteArrayOutputStream stream = new ByteArrayOutputStream();
                @Override
                public byte[] getSignature() {

                    byte[] dtbs = stream.toByteArray();
                    try {
                        System.out.println(Base64.getEncoder().encodeToString(content.readAllBytes()));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    System.out.println(Base64.getEncoder().encodeToString(dtbs));
                    byte[] hash = digest.digest(dtbs);
                    return remoteSign(Base64.getEncoder().encodeToString(hash));
                }

                @Override
                public OutputStream getOutputStream() {
                    return stream;
                }

                @Override
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));
                }
            };

            List<X509Certificate> certChain = cerFileToCertChain();
            X509Certificate cert = certChain.get(0);

            ESSCertIDv2 certid = new ESSCertIDv2(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
                    MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())
            );
            SigningCertificateV2 sigCert = new SigningCertificateV2(certid);
            Attribute attr = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(sigCert));

            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(attr);
            AttributeTable attributeTable = new AttributeTable(v);
            CMSAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator(attributeTable);

            org.bouncycastle.asn1.x509.Certificate cert2 = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));
            JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
            sigb.setSignedAttributeGenerator(attrGen);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(new JcaCertStore(certChain));
            gen.addSignerInfoGenerator(sigb.build(contentSigner, new X509CertificateHolder(cert2)));

            CMSTypedData msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);

            return signedData.getEncoded();

        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private byte[] remoteSign(String hash) {
        try {
            byte[] hashBytes = Base64.getDecoder().decode(hash);
            System.out.println(hash);
            // TODO: Call external signing service here

            // But for demo purposes we use RSA private key
            // We need to sign pre-hashed data, so we need to use NONEwithRSA
            Signature sig = Signature.getInstance("NONEwithRSA");
            sig.initSign(loadPrivateKey());
            // Sign a pre-hashed value must be encoded in ASN.1 DER format
            byte[] hashWrapped = wrapForRsaSign(hashBytes);
            sig.update(hashWrapped);
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }


    private List<X509Certificate> cerFileToCertChain() {
        String certPath = "";
        try (InputStream inStream = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (List<X509Certificate>) cf.generateCertificates(inStream);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private PrivateKey loadPrivateKey() {

        String privateKeyPath = "";
        try (Reader reader = new FileReader(privateKeyPath, StandardCharsets.UTF_8);
             PemReader pemReader = new PemReader(reader)) {

            // Parse the PEM file and get the key content
            PemObject pemObject = pemReader.readPemObject();
            byte[] keyBytes = pemObject.getContent();


            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(keyBytes);
            return kf.generatePrivate(privSpec);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }


    private byte[] wrapForRsaSign(byte[] dig) throws IOException {

//        SEQUENCE {
//            SEQUENCE {
//                AlgorithmIdentifier {
//                    algorithm OBJECT IDENTIFIER,
//                            parameters NULL
//                },
//            },
//            Digest OCTET STRING
//        }


        ASN1ObjectIdentifier oid = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256").getAlgorithm();

        ASN1EncodableVector algIdentifier = new ASN1EncodableVector();
        algIdentifier.add(oid); // OID for the algorithm
        algIdentifier.add(DERNull.INSTANCE); // NULL parameters

        ASN1EncodableVector digestInfo = new ASN1EncodableVector();
        digestInfo.add(new DERSequence(algIdentifier)); // AlgorithmIdentifier sequence
        digestInfo.add(new DEROctetString(dig)); // Actual digest as OCTET STRING

        // Encode the full structure into bytes
        return new DERSequence(digestInfo).getEncoded();
    }

}
