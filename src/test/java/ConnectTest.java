import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

import junit.framework.TestCase;

import org.apache.axis.transport.http.HTTPTransport;

import com.fasterxml.jackson.core.JsonFactory;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.PemReader;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.Directory.Users.List;
import com.google.api.services.admin.directory.DirectoryScopes;
import com.google.api.services.admin.directory.model.User;
import com.google.api.services.admin.directory.model.UserName;
import com.google.api.services.admin.directory.model.Users;

public class ConnectTest extends TestCase  {

	public void testConnect () throws GeneralSecurityException, IOException
	{
		HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
		JacksonFactory jsonFactory = JacksonFactory.getDefaultInstance();
		
		File f = new File("src/test/resources/secrets.json");
		File f2 = new File("src/test/resources/privatekey.pem");

		if (f.canRead())
		{
			// Build service account credential.
			GoogleCredential credential = new GoogleCredential.Builder()
					.setTransport(httpTransport)
					.setJsonFactory(jsonFactory)
					.setServiceAccountId("37045804422-dfrqgn48kjrm6oj8gbjib9mjun20gabe@developer.gserviceaccount.com")
					.setServiceAccountScopes(Collections.singleton(DirectoryScopes.ADMIN_DIRECTORY_USER))
					.setServiceAccountPrivateKeyFromPemFile(f2)
					.setServiceAccountUser("admin@soffid.com")
					.build();
			
			Directory d = new Directory.Builder (httpTransport, jsonFactory, credential)
				.setApplicationName("soffid.com:api-project-37045804422")
				.build();
			
			Users users = d.users()
					.list()
					.setDomain("soffid.com")
					.setQuery("email=admin@soffid.com")
					.execute();
			for (User o: users.getUsers())
			{
				System.out.println ("user: "+o);
				System.out.println ("EMAIL = "+o.get("emails"));
			}
			
//			User u = d.users().list().setQuery("primaryEmail = \"admin@soffid.com\"").execute();
			User u = d.users().get("admin@soffid.com").execute();
			if (u != null)
			{
				System.out.println ("Modifying "+u.getId());
				User u2 = new User();
				u2.setName(new UserName());
				u2.getName().setFullName("David Macho");
				u2.getName().setFamilyName("Macho");
				u2.setId(u.getId());
				d.users().patch(u.getId(), u2).execute();
			}
		}
		else
		{
			System.out.println ("Private key not found. Skipping test");
		}
		
	}
}
