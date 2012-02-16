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
		System.out.println("********** 证书管理工具v1.0 **********");
		System.out.println("1. 初始化向导");
		System.out.println("2. 创建服务器证书 (jks)");
		System.out.println("3. 创建管理员证书 (pfx)");
		System.out.println("0. 退出");
		System.out.println("************************************");
		System.out.print("请选择>");
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
				System.out.println("输入错误");
				break;
			}
			
			if(select != 99) {
				System.out.println("按任意键继续...");
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
		String caSubject = getUserInput("CA证书主题", "CN=DemoCA,O=EMV,C=CN");
		String caValidate = getUserInput("CA证书有效期天数", "3650");
		String serverIP = getUserInput("CA服务器IP地址", "127.0.0.1");
		String serverSubject = "CN=" + serverIP + ",O=EMV,C=CN";
		String serverValidate = getUserInput("服务器证书有效期天数", "3650");
		String adminSubject = "CN=SuperAdmin,O=EMV,C=CN";
		String adminValidate = getUserInput("超级管理员证书有效期天数", "3650");
		String dbIP = getUserInput("数据库服务器IP地址", "127.0.0.1");
		String dbPort = getUserInput("数据库服务端口", "1521");
		String dbSID = getUserInput("数据库服务标识(SID)", "orcl");
		String dbUser = getUserInput("数据库用户名", "emvca");
		String dbPassword = getUserInput("数据库用户口令", "11111111");
		
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
		System.out.println("请输入" + info + "(默认" + defaultValue + "):");
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
			System.out.println("未发现可用CA证书，请先创建CA证书");
			return;
		}		
		
		System.out.println("请输入服务器证书主题:(例.CN=192.168.1.2,O=TEST,C=CN)");
		Scanner scanner = new Scanner(System.in);
		String subject = scanner.next().trim();
		
		System.out.println("请输入服务器证书有效期(天):(例.3650)");
		int validate = scanner.nextInt();
		
		System.out.println("请输入服务器证书保存文件名:(例. server.jks)");
		String fileName = scanner.next();
		
		System.out.println("请输入服务器证书保护口令:");
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
			System.out.println("未发现可用CA证书，请先创建CA证书");
			return;
		}
		
		System.out.println("请输入管理员证书主题:(例.CN=SuperAdmin,O=TEST,C=CN)");
		Scanner scanner = new Scanner(System.in);
		String subject = scanner.next().trim();
		
		System.out.println("请输入管理员证书有效期(天):(例.3650)");
		int validate = scanner.nextInt();
		
		System.out.println("请输入管理员证书保存文件名:(例.admin.pfx)");
		String fileName = scanner.next();
		
		System.out.println("请输入管理员证书保护口令:");
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
