package org.mockserver.server;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Service;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.configuration.ConfigurationProperties;
import org.mockserver.echo.http.EchoServer;
import org.mockserver.socket.PortFactory;
import org.mockserver.socket.SSLFactory;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;

import javax.net.ssl.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


/**
 * @author jamesdbloom
 */
public class ClientServerWarWithSslMockIntegrationTest  {

    private final static int SERVER_HTTPS_PORT = 1080;
    private final static int TEST_SERVER_HTTP_PORT = PortFactory.findFreePort();
    private static Tomcat tomcat;
    private static EchoServer echoServer;

    final static HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
    	public boolean verify(String hostname, SSLSession session) {
    		return true;
    	}
    };

    /**
     * Trust every server - dont check for any certificate
     */
    private static void trustAllHosts() {
    	// Create a trust manager that does not validate certificate chains
    	TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
    		public java.security.cert.X509Certificate[] getAcceptedIssuers() {
    			return new java.security.cert.X509Certificate[] {};
    		}

			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				
			}
    	} };

    	// Install the all-trusting trust manager
    	try {
    		SSLContext sc = SSLContext.getInstance("TLS");
    		sc.init(null, trustAllCerts, new java.security.SecureRandom());
    		HttpsURLConnection
    				.setDefaultSSLSocketFactory(sc.getSocketFactory());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    }
    
    @BeforeClass
    public static void startServer() throws Exception, LifecycleException {
    	String servletContext = "";

        tomcat = new Tomcat();
        tomcat.setBaseDir(new File(".").getCanonicalPath() + File.separatorChar + "tomcat" + (servletContext.length() > 0 ? "_" + servletContext : ""));

        // add http port
        tomcat.setPort(SERVER_HTTPS_PORT);

        // add servlet
        Context ctx = tomcat.addContext("/" + servletContext, new File(".").getAbsolutePath());
        tomcat.addServlet("/" + servletContext, "mockServerServlet", new MockServerServlet());
        ctx.addServletMapping("/*", "mockServerServlet");

        // start server
        tomcat.start();

        // start test server
        echoServer = new EchoServer(TEST_SERVER_HTTP_PORT, false);

             
        // start client
        MockServerClient mockServerClient = new MockServerClient("127.0.0.1", SERVER_HTTPS_PORT);
        
        mockServerClient
        .when(
            request()
                .withMethod("POST"))
        .respond(
            response()
                .withStatusCode(200)
                .withHeader("Content-Type",
                    "application/json; charset=utf-8")
                .withBody(
                    "{\"status\":\"success\",\"data\":{\"access_token\":\"4e8606624e3bcbb0da0e844a9de2521c0c42f9c0\"}}"));

       
        /*defaultConnector.setSecure(true);
        defaultConnector.setAttribute("keyAlias", SSLFactory.KEY_STORE_CERT_ALIAS);
        defaultConnector.setAttribute("keystorePass", ConfigurationProperties.javaKeyStorePassword());
        defaultConnector.setAttribute("keystoreFile", new File("C:\\Program Files\\Java\\jdk1.7.0_79\\jre\\lib\\security\\cacerts").getAbsoluteFile());
        defaultConnector.setAttribute("sslProtocol", "TLS");
        defaultConnector.setAttribute("clientAuth", false);
        defaultConnector.setAttribute("SSLEnabled", true);
        defaultConnector.setAttribute("scheme", "https");
        defaultConnector.setAttribute("protocol", "HTTP/1.1");*/
        
        // add https connector
        Connector defaultConnector = tomcat.getConnector();
        
        SSLFactory.getInstance().buildKeyStore();
        defaultConnector.setPort(SERVER_HTTPS_PORT);
        defaultConnector.setSecure(true);
        defaultConnector.setAttribute("keyAlias", SSLFactory.KEY_STORE_CERT_ALIAS);
        defaultConnector.setAttribute("keystorePass", ConfigurationProperties.javaKeyStorePassword());
        defaultConnector.setAttribute("keystoreFile", new File(ConfigurationProperties.javaKeyStoreFilePath()).getAbsoluteFile());
        defaultConnector.setAttribute("sslProtocol", "TLS");
        defaultConnector.setAttribute("clientAuth", false);
        defaultConnector.setAttribute("SSLEnabled", true);
        defaultConnector.setScheme("https");
        tomcat.setConnector(defaultConnector);
    }

    @Test
    public void test() throws InterruptedException, IOException {
    	URL url = new URL("https://auth.temafon.ru/?r=api/login&request_type=password&approve_require=false");
    	
    	//URL url = new URL("https://127.0.0.1:1080");
    	
       	trustAllHosts();
		Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 1080));

		HttpsURLConnection https = (HttpsURLConnection) url.openConnection(proxy);

		https.setHostnameVerifier(DO_NOT_VERIFY);
		https.setRequestMethod("POST");
		https.setDoInput(true);
		https.setDoOutput(true);
		https.addRequestProperty("Authorization", "Basic bG9jYXRvcjpua1MxRUFwWGpvOGpiZFREY2Q1ZThncW1vMzROczk=");
		https.addRequestProperty("User-Agent", "ru.beeline.newlocator/1.0.prerelease_764_feature/LOC-1599_8b38a1a build 764/Android 6.0.1/a62c6c47-3e4f-41ae-8f00-01b9793aecf5.1461711146667");

		https.connect();

	    OutputStream os = https.getOutputStream();
	    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
	    writer.write("msisdn=74946151646&password=%D0%BE");
	
	    writer.flush();
	    writer.close();
	    os.close();
	   	    
	    InputStream response = https.getInputStream();
	    try (BufferedReader reader = new BufferedReader(new InputStreamReader(response, "utf-8"))) {
	        for (String line; (line = reader.readLine()) != null;) {
	            System.out.println(line);
	        }
	    }


    	Thread.sleep(1000);

    }
    
    @AfterClass
    public static void stopServer() throws Exception {
        // stop mock server
        tomcat.stop();
        tomcat.getServer().await();

        // stop test server
        echoServer.stop();
    }
}
