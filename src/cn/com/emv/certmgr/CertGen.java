package cn.com.emv.certmgr;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import cn.com.jit.ida.util.pki.Parser;
import cn.com.jit.ida.util.pki.cert.X509Cert;
import cn.com.jit.ida.util.pki.cert.X509CertGenerator;
import cn.com.jit.ida.util.pki.cipher.JCrypto;
import cn.com.jit.ida.util.pki.cipher.JKey;
import cn.com.jit.ida.util.pki.cipher.JKeyPair;
import cn.com.jit.ida.util.pki.cipher.Mechanism;
import cn.com.jit.ida.util.pki.cipher.Session;
import cn.com.jit.ida.util.pki.extension.AuthorityKeyIdentifierExt;
import cn.com.jit.ida.util.pki.extension.BasicConstraintsExt;
import cn.com.jit.ida.util.pki.extension.CRLDistPointExt;
import cn.com.jit.ida.util.pki.extension.CRLDistributionPointsExt;
import cn.com.jit.ida.util.pki.extension.DistributionPointExt;
import cn.com.jit.ida.util.pki.extension.KeyUsageExt;
import cn.com.jit.ida.util.pki.extension.SubjectKeyIdentifierExt;
import cn.com.jit.ida.util.pki.pkcs.PKCS12;

public class CertGen {
	
	public static final String ROOTCERT_TAG = "rootcert";
	public static final String ROOTCERT_JKS = "./certs/rootcert.jks";
	public static final String ROOTCERT_CERT = "./certs/rootcert.cer";
	public static final String ROOTCERT_PASSWORD = "11111111";
	
	
	public X509Cert rootCert;
	public JKey rootPrvKey;
	public JKey rootPubKey;
	
	public static CertGen instance;
	
	private CertGen() {
		try {
			JCrypto.getInstance().initialize(JCrypto.JSOFT_LIB, null);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	public static CertGen getInstance() {
		if(instance == null) {
			synchronized(CertGen.class) {
				if(instance == null) {
					instance = new CertGen();
				}
			}
		}
		return instance;
	}
	
	public void loadRootCert() {
		try {
			File file = new File(ROOTCERT_JKS);
			if(file.exists()) {
				KeyStore keyStore = KeyStore.getInstance("JKS");
				FileInputStream fin = new FileInputStream(ROOTCERT_JKS);
				keyStore.load(fin, ROOTCERT_PASSWORD.toCharArray());
				fin.close();
				
				Key key = keyStore.getKey(ROOTCERT_TAG, ROOTCERT_PASSWORD.toCharArray());
				Certificate cert = keyStore.getCertificate(ROOTCERT_TAG);
				
				rootPrvKey = new JKey(JKey.RSA_PRV_KEY, key.getEncoded());
				rootCert = new X509Cert(cert.getEncoded());
				rootPubKey = rootCert.getPublicKey();
				System.out.println("加载CA证书成功");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	public void genRootCert(String subject, int days) {
		try {
			Session session = JCrypto.getInstance().openSession(JCrypto.JSOFT_LIB);
			Mechanism m = new Mechanism(Mechanism.RSA);
			JKeyPair keyPair = session.generateKeyPair(m, 1024);
			this.rootPrvKey = keyPair.getPrivateKey();
			this.rootPubKey = keyPair.getPublicKey();
			
			X509CertGenerator generator = new X509CertGenerator();
			generator.setSerialNumber(CodeGenerator.generateSerialNumber());
			generator.setSubject(subject);
			generator.setIssuer(subject);
			
			Date notBefore = new Date();
			GregorianCalendar calander = new GregorianCalendar();
			calander.add(Calendar.DATE, days);			
			Date notAfter = calander.getTime();
			generator.setNotBefore(notBefore);
			generator.setNotAfter(notAfter);
			
			generator.setSignatureAlg(Mechanism.SHA1_RSA);
			
			generator.setPublicKey(rootPubKey);
			
			// extensions
			AuthorityKeyIdentifierExt authKeyIdExt = new AuthorityKeyIdentifierExt(rootPubKey);
			generator.addExtensiond(authKeyIdExt);
			
			SubjectKeyIdentifierExt spkiExt = new SubjectKeyIdentifierExt(rootPubKey);
			generator.addExtensiond(spkiExt);
			
			BasicConstraintsExt basicConExt = new BasicConstraintsExt(true);
			generator.addExtensiond(basicConExt);
			
			KeyUsageExt keyUsageExt = new KeyUsageExt();
			keyUsageExt.addKeyUsage(KeyUsageExt.DIGITAL_SIGNATURE);
			keyUsageExt.addKeyUsage(KeyUsageExt.KEY_CERT_SIGN);
			keyUsageExt.addKeyUsage(KeyUsageExt.CRL_SIGN);
			//keyUsageExt.setCritical(true);
			generator.addExtensiond(keyUsageExt);
			
			byte[] certData = generator.generateX509Cert(rootPrvKey, session);
			rootCert = new X509Cert(certData);
			
			FileOutputStream fous = new FileOutputStream(ROOTCERT_CERT);
			fous.write(certData);
			fous.flush();
			fous.close();
			
			File file = new File(ROOTCERT_JKS);
			file.createNewFile();
			
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null, null);
			Key key = Parser.convertPrivateKey(rootPrvKey);
			Certificate cert = convert2JavaCert(rootCert);
			ks.setKeyEntry(ROOTCERT_TAG, key, ROOTCERT_PASSWORD.toCharArray(), new Certificate[]{cert});
			
			fous = new FileOutputStream(file);
			ks.store(fous, ROOTCERT_PASSWORD.toCharArray());
			fous.flush();
			fous.close();
			
			System.out.println("产生CA证书成功.");
			System.out.println("证书文件保存路径:" + new File(ROOTCERT_CERT).getAbsolutePath());
			System.out.println("keystore保存路径:" + new File(ROOTCERT_JKS).getAbsolutePath());
			System.out.println("keystore保护口令:" + ROOTCERT_PASSWORD);
		} catch (Exception ex) {
			ex.printStackTrace();			
		}
	}
	
	public X509Cert getRootCert() {
		return rootCert;
	}

	public void setRootCert(X509Cert rootCert) {
		this.rootCert = rootCert;
	}

	public X509Cert genCommonCert(String subject, int days, String password, CertTypeEnum type, String fileName) {
		try {
			if(rootPrvKey == null) {
				System.out.println("未发现可用CA证书，请先创建CA证书.");
				return null;
			}
			
			Mechanism m = new Mechanism(Mechanism.RSA);
			Session session = JCrypto.getInstance().openSession(JCrypto.JSOFT_LIB);
			JKeyPair certKeyPair = session.generateKeyPair(m, 1024);
			
			X509CertGenerator generator = new X509CertGenerator();
			generator.setSerialNumber(CodeGenerator.generateSerialNumber());
			generator.setSubject(subject);
			generator.setIssuer(rootCert.getSubject());
			
			Date notBefore = new Date();
			GregorianCalendar calander = new GregorianCalendar();
			calander.add(Calendar.DATE, days);			
			Date notAfter = calander.getTime();
			generator.setNotBefore(notBefore);
			generator.setNotAfter(notAfter);
			
			generator.setSignatureAlg(Mechanism.SHA1_RSA);
			
			generator.setPublicKey(certKeyPair.getPublicKey());
			
			// extensions
			AuthorityKeyIdentifierExt authKeyIdExt = new AuthorityKeyIdentifierExt(rootPubKey);
			generator.addExtensiond(authKeyIdExt);
			
			SubjectKeyIdentifierExt spkiExt = new SubjectKeyIdentifierExt(certKeyPair.getPublicKey());
			generator.addExtensiond(spkiExt);
			
			byte[] certData = generator.generateX509Cert(rootPrvKey, session);
			X509Cert commonCert = new X509Cert(certData);

			if(type == CertTypeEnum.JKS) {
				File file = new File(fileName);
				file.createNewFile();
				
				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(null, null);
				Key key = Parser.convertPrivateKey(certKeyPair.getPrivateKey());
				Certificate cert = convert2JavaCert(commonCert);
				ks.setKeyEntry(subject.toLowerCase(), key, password.toCharArray(), new Certificate[]{cert});
				
				Certificate caCert = convert2JavaCert(rootCert);
				ks.setCertificateEntry("ca cert", caCert);
				
				
				FileOutputStream fous = new FileOutputStream(file);
				ks.store(fous, password.toCharArray());
				fous.flush();
				fous.close();
				
				System.out.println("产生JKS文件成功.");
				System.out.println("keystore文件路径:" + file.getAbsolutePath());
				System.out.println("keystore保护口令:" + password);
			} else if(type == CertTypeEnum.PFX) {
				PKCS12 p12 = new PKCS12();				
				X509Cert[] certs = new X509Cert[] {commonCert, rootCert};
				p12.generatePfxFile(certKeyPair.getPrivateKey(), certs, password.toCharArray(), fileName);
				
				System.out.println("产生PFX文件成功.");
				System.out.println("pfx文件路径:" + new File("./certs/" + fileName).getAbsolutePath());
				System.out.println("pfx保护口令:" + password);
			}			
			
			return commonCert;
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}
	
	private Certificate convert2JavaCert(X509Cert jitCert) throws Exception {           
        ByteArrayInputStream inputStream = new ByteArrayInputStream(jitCert.getEncoded());
        CertificateFactory certFac = CertificateFactory.getInstance("X.509");
        Certificate javaCert = certFac.generateCertificate(inputStream);        
        return javaCert;
    }
	
}