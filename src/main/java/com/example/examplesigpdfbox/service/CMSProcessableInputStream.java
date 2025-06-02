package com.example.examplesigpdfbox.service;

import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class CMSProcessableInputStream implements CMSTypedData {
    private final ASN1ObjectIdentifier contentType;
    private final InputStream in;
    public CMSProcessableInputStream(InputStream is) {
        this(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), is);
    }

    CMSProcessableInputStream(ASN1ObjectIdentifier type, InputStream is) {
        contentType = type;
        in = is;
    }

    @Override
    public Object getContent() {
        return in;
    }

    @Override
    public void write(OutputStream out) throws IOException, CMSException {
        IOUtils.copy(in, out);
        in.close();
    }

    @Override
    public ASN1ObjectIdentifier getContentType() {
        return contentType;
    }
}
