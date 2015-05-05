import java.io.IOException;
import java.io.StringReader;

import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;

import junit.framework.TestCase;


public class PEMReaderTest extends TestCase {
	public void test1() throws IOException
	{
		String key = "-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANG0B6Pr65TuBnya\nJ4OdB86GJhL8VIUG1aUXf46ITDHHvm+5jt1RX92GGOJaXsuZzwD4MJkUpC6C+THN\nWkPtLx4eHw0p+7Nk8pkBPhco6FKNCKtmO2hABGHk248wXsJgjlaOaO5QFYBla4Cv\ndX/AZxuWu3ikYcgACBLzAGOALOQrAgMBAAECgYAhakmJYk+AxMj90+aV/1C+JPwu\nLE0fgW5Lx0nJIYjaqdR7oxrTw2K+Pt76OqI+WTz2D5ZW3kYnLzGcMPfAOSw3m3m/\nj61LYl9b7xRycmtWXbbdr/x70Yxv8fZhzXo/eLLbHzXRQ6fPOpQia+hCP+7+CFEP\nXXrk+gUzD8kDm6bBwQJBAPDP66AlpRiAeSQRoHaIR/qPPi5+WtEI7QQsgP/RonJm\n6hPymerCW+vK15UG0ygc8OSi3Er9fEakGI2LA+J3hMsCQQDe7dV8SI8zmEkJaYPj\ne2d6pBiAOObyGf0qdogmf9CarPsGnEQIiZEDgpTzomtiAn0Ua21LJIxSG86KhZeW\n+5IhAkAHz9bm9RGr/87uOpwn/DfJiwgLXhH4If/+WKs+oUBR0cDaMM6JbRCqT4Q6\n02PaM0YlRJs824hCimQ5gz73A8WNAkEAxGIV0A+HfzcnGBCIq+v5I5PNNZ9q61mz\nqSWUGP49wRSjapZcZHzzb3koSFwLZuK0VzmvpSOELYzrbSH0gYAKoQJBAOhlE6IA\n2z0snMbv4dqiq2MyZ94LVVfIqkUcU/L/RvcamIDYtqw+tNkM41PoWaQeqVjZDOT/\nXiVhYOgbZfgK+6E=\n-----END PRIVATE KEY-----";
		
		PemReader pr = new PemReader(new StringReader(key));
		Section s = pr.readNextSection();
		
		System.out.println (s);
	}

}
