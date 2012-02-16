package cn.com.emv.certmgr;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import cn.com.jit.ida.util.pki.cert.X509Cert;
import freemarker.template.Configuration;
import freemarker.template.DefaultObjectWrapper;
import freemarker.template.Template;

public class Console {
	
	private void showMenu() {
		System.out.println("********** ֤���������v1.0 **********");
		System.out.println("1. ��ʼ����");
		System.out.println("2. ����������֤�� (jks)");
		System.out.println("3. ��������Ա֤�� (pfx)");
		System.out.println("0. �˳�");
		System.out.println("************************************");
		System.out.print("��ѡ��>");
	}
	
	private int getUserSelect() {
		try {
			Scanner scanner = new Scanner(System.in);
			int select = scanner.nextInt();
			return select;
		} catch (Exception ex) {
			return -1;
		}
	}
	
	
	
	public void start() {
		try {
			File file = new File(CertGen.ROOTCERT_JKS);
			if(file.exists()) {
				CertGen generator = CertGen.getInstance();
				generator.loadRootCert();
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
		int select = 99;
		while(select != 0) {
			switch (select) {
			case 99:
				// start
				break;
			case 1:
				this.doInit();
				break;
			case 2:
				this.genServerCert();
				break;
			case 3:
				this.genAdminCert();
				break;
			default:
				System.out.println("�������");
				break;
			}
			
			if(select != 99) {
				System.out.println("�����������...");
				try {
					System.in.read();
				} catch (Exception ex) {
					// do nothing
				}
			}
			this.showMenu();
			select = this.getUserSelect();
		}
		System.out.println("ByeBye.");
	}
	
	private void doInit() {
		String caSubject = getUserInput("CA֤������", "CN=DemoCA,O=EMV,C=CN");
		String caValidate = getUserInput("CA֤����Ч������", "3650");
		String serverIP = getUserInput("CA������IP��ַ", "127.0.0.1");
		String serverSubject = "CN=" + serverIP + ",O=EMV,C=CN";
		String serverValidate = getUserInput("������֤����Ч������", "3650");
		String adminSubject = "CN=SuperAdmin,O=EMV,C=CN";
		String adminValidate = getUserInput("��������Ա֤����Ч������", "3650");
		String dbIP = getUserInput("���ݿ������IP��ַ", "127.0.0.1");
		String dbPort = getUserInput("���ݿ����˿�", "1521");
		String dbSID = getUserInput("���ݿ�����ʶ(SID)", "orcl");
		String dbUser = getUserInput("���ݿ��û���", "emvca");
		String dbPassword = getUserInput("���ݿ��û�����", "11111111");
		
		File file = new File("./init_file/sql/");
		if(!file.exists()) {
			file.mkdirs();
		}
		
		CertGen generator = CertGen.getInstance();
		// generate root cert
		generator.genRootCert(caSubject, Integer.parseInt(caValidate));
		// generate server cert
		X509Cert serverCert = generator.genCommonCert(serverSubject, Integer.parseInt(serverValidate), "11111111", CertTypeEnum.JKS, "./init_file/server.jks");
		// generate admin cert
		X509Cert adminCert = generator.genCommonCert(adminSubject, Integer.parseInt(adminValidate), "11111111", CertTypeEnum.PFX, "./init_file/superAdmin.pfx");
		// generate sql file
		genSQLFile(serverCert, adminCert);
		// generate datasource file
		genDataSourceFile(dbIP, dbPort, dbSID, dbUser, dbPassword);
		
	}
	
	private void genSQLFile(X509Cert serverCert, X509Cert adminCert) {
		try {
			Configuration config = new Configuration();
			config.setDirectoryForTemplateLoading(new File("./ftl"));
			config.setObjectWrapper(new DefaultObjectWrapper());
			
			Template template = config.getTemplate("create_tables.ftl");
			
			Map<String, String> data = new HashMap<String, String>();
			data.put("commCertSN", serverCert.getSerialNumber().toString(16));
			data.put("commCertSubject", serverCert.getSubject());
			data.put("adminCertSN", adminCert.getSerialNumber().toString(16));
			data.put("adminCertSubject", adminCert.getSubject());
			
			Writer writer = new OutputStreamWriter(new FileOutputStream("./init_file/sql/create_tables.sql"));
			template.process(data, writer);
			writer.flush();
			writer.close();
			
			File dropFile = new File("./ftl/drop_tables.ftl");
			FileInputStream fin = new FileInputStream(dropFile);
			byte[] fdata = new byte[fin.available()];
			fin.read(fdata);
			fin.close();
			
			FileOutputStream fous = new FileOutputStream("./init_file/sql/drop_tables.sql");
			fous.write(fdata);
			fous.flush();
			fous.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	private void genDataSourceFile(String dbIP, String dbPort, String dbSID, String dbUser, String dbPassword) {
		try {
			Configuration config = new Configuration();
			config.setDirectoryForTemplateLoading(new File("./ftl"));
			config.setObjectWrapper(new DefaultObjectWrapper());
			
			Template template = config.getTemplate("ca-datasource.ftl");
			
			Map<String, String> data = new HashMap<String, String>();
			data.put("dbIP", dbIP);
			data.put("dbPort", dbPort);
			data.put("dbSID", dbSID);
			data.put("dbUser", dbUser);
			data.put("dbPassword", dbPassword);
			
			Writer writer = new OutputStreamWriter(new FileOutputStream("./init_file/Tomcat/emvca/spring/ca-datasource.xml"));
			template.process(data, writer);
			writer.flush();
			writer.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	private String getUserInput(String info, String defaultValue) {
		System.out.println("������" + info + "(Ĭ��" + defaultValue + "):");
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		String input = null;
		try {
			input = reader.readLine();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		if(input != null && !input.trim().equals("")) {
			return input;
		} else {
			return defaultValue;
		}
	}
	
	private void genServerCert() {
		CertGen generator = CertGen.getInstance();
		if(generator.getRootCert() == null) {
			System.out.println("δ���ֿ���CA֤�飬���ȴ���CA֤��");
			return;
		}		
		
		System.out.println("�����������֤������:(��.CN=192.168.1.2,O=TEST,C=CN)");
		Scanner scanner = new Scanner(System.in);
		String subject = scanner.next().trim();
		
		System.out.println("�����������֤����Ч��(��):(��.3650)");
		int validate = scanner.nextInt();
		
		System.out.println("�����������֤�鱣���ļ���:(��. server.jks)");
		String fileName = scanner.next();
		
		System.out.println("�����������֤�鱣������:");
		String password = scanner.next();
		
		X509Cert cert = generator.genCommonCert(subject, validate, password, CertTypeEnum.JKS, "./certs/" + fileName);
		
		String cFile = "./certs/" + fileName.substring(0, fileName.length() - 4) + ".cer";
		try {
			FileOutputStream fous = new FileOutputStream(cFile);
			fous.write(cert.getEncoded());
			fous.flush();
			fous.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	private void genAdminCert() {
		CertGen generator = CertGen.getInstance();
		if(generator.getRootCert() == null) {
			System.out.println("δ���ֿ���CA֤�飬���ȴ���CA֤��");
			return;
		}
		
		System.out.println("���������Ա֤������:(��.CN=SuperAdmin,O=TEST,C=CN)");
		Scanner scanner = new Scanner(System.in);
		String subject = scanner.next().trim();
		
		System.out.println("���������Ա֤����Ч��(��):(��.3650)");
		int validate = scanner.nextInt();
		
		System.out.println("���������Ա֤�鱣���ļ���:(��.admin.pfx)");
		String fileName = scanner.next();
		
		System.out.println("���������Ա֤�鱣������:");
		String password = scanner.next();
		
		X509Cert cert = generator.genCommonCert(subject, validate, password, CertTypeEnum.PFX, "./certs/" + fileName);
		
		String cFile = "./certs/" + fileName.substring(0, fileName.length() - 4) + ".cer";
		try {
			FileOutputStream fous = new FileOutputStream(cFile);
			fous.write(cert.getEncoded());
			fous.flush();
			fous.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		Console console = new Console();
		console.start();
	}

}