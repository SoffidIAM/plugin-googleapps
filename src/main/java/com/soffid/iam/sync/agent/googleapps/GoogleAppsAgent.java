package com.soffid.iam.sync.agent.googleapps;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.xml.rpc.ServiceException;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Hex;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.DirectoryScopes;
import com.google.api.services.admin.directory.model.Group;
import com.google.api.services.admin.directory.model.Member;
import com.google.api.services.admin.directory.model.Members;
import com.google.api.services.admin.directory.model.OrgUnit;
import com.google.api.services.admin.directory.model.User;
import com.google.api.services.admin.directory.model.Users;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownGroupException;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.TimedOutException;

public class GoogleAppsAgent extends es.caib.seycon.ng.sync.agent.Agent
		implements UserMgr, MailAliasMgr, GroupMgr, ExtensibleObjectMgr {

	private static final String APPS_APPLICATION_NAME = "SOFFID-SYNCSERVER-1_0";// [company-id]-[app-name]-[app-version]

	private String adminUser;
	private PrivateKey privateKey;
	private String accountId;

	private Directory getDirectory() {
		return new Directory.Builder (httpTransport, jsonFactory, googleCredential)
			.setApplicationName(APPS_APPLICATION_NAME)
			.build();

	}

	private String customerId = null; // L'obtenim en el mètod init()
	private String adminEmail;

	private NetHttpTransport httpTransport;

	private JacksonFactory jsonFactory;

	private String googleDomain;

	private Collection<ExtensibleObjectMapping> objectMappings;

	private ObjectTranslator objectTranslator;

	private GoogleCredential googleCredential;

	/**
	 * Paràmetres [0] user Administrador [1] admin Password [2] dominiGoogle
	 * 
	 * @param params
	 */
	public GoogleAppsAgent() throws java.rmi.RemoteException {
	}

	public void init() throws Exception {
		super.init();

		httpTransport = GoogleNetHttpTransport.newTrustedTransport();
		jsonFactory = JacksonFactory.getDefaultInstance();

		this.adminUser = getDispatcher().getParam0();
		this.accountId = getDispatcher().getParam1();
	
		try {
			String pk = getDispatcher().getParam2().replaceAll("\\\\n", "\n");
			PEMReader pemReader = new PEMReader(new StringReader (pk));
			KeyPair keyPair =  (KeyPair) pemReader.readObject();
			privateKey = keyPair.getPrivate();
		} catch (Throwable t) {
			throw new InternalErrorException("Error parsing private key", t);
		}
		
		googleDomain = getDispatcher().getParam3();
		// comprovem el domini
		if (googleDomain == null
				|| (googleDomain != null && "".equals(googleDomain.trim())))
			throw new InternalErrorException(
					"Missing google domain configuration parameter");


		googleCredential = new GoogleCredential.Builder()
		.setTransport(httpTransport)
		.setJsonFactory(jsonFactory)
		.setServiceAccountId(accountId)
		.setServiceAccountScopes(Arrays.asList(
				new String [] {
						DirectoryScopes.ADMIN_DIRECTORY_USER,
						DirectoryScopes.ADMIN_DIRECTORY_ORGUNIT,
						DirectoryScopes.ADMIN_DIRECTORY_GROUP,
						DirectoryScopes.ADMIN_DIRECTORY_GROUP_MEMBER
				}
				))
		.setServiceAccountPrivateKey(privateKey)
		.setServiceAccountUser(adminUser)
		.build();
		

		User u;
		try {
			u = getDirectory().users().get(adminUser).execute();
		} catch (Throwable t)
		{
			throw new InternalErrorException ("Error testing google credentials", t);
		}
			
		if ( u == null)
			throw new InternalErrorException ("User not found "+adminUser);
		customerId = u.getCustomerId();
		
	}

	public void updateUser(String account, Usuari user) throws RemoteException,
			InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		ExtensibleObject sourceObject = new UserExtensibleObject(acc, user, getServer());
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_USER) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateGoogleUser(account, acc, user, obj);
					}
					else
					{
						disableUser(acc.getName());
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	protected void updateGoogleUser (String account, Account acc, Usuari ui, ExtensibleObject obj) throws InternalErrorException
	{

		boolean active;

		Rol roles[] = null;

		try {
			// Mirem si ja existeix l'usuari a google

			String[] split = account.split("@");
			String accountName = split[0];
			String accountDomain = split.length > 1 ? split[1] : googleDomain;
			User user = retrieveUser(accountName, accountDomain);

			boolean hasAlias = false;

			if (user == null) { // USUARI NOU
				log.info("l'usuari {} no existeix a google, el creem", account,
						null);
				// Donem d'alta a l'usuari en google
				Password password = getServer().getOrGenerateUserPassword(
						account, getCodi());
				
				user = new User();
				for (String key: obj.keySet())
				{
					user.set(key, obj.get(key));
				}
				
				if (! obj.containsKey("orgUnitPath") && ui != null)
				{
					user.setOrgUnitPath( getOrgUnitPathString(ui.getCodiGrupPrimari(), true) );
				}
				getDirectory().users().insert(user).execute();
			} else { // USUARI EXISTENT
				for (String key: obj.keySet())
				{
					if (! key.equals("id"))
						user.set(key, obj.get(key));
				}
				if (! obj.containsKey("orgUnitPath") && ui != null)
				{
					user.setOrgUnitPath( getOrgUnitPathString (ui.getCodiGrupPrimari(), true) );
				}
				getDirectory().users().patch(user.getId(), user).execute();
			}

		} catch (InternalErrorException e) {
			e.printStackTrace();
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(e.getMessage(), e);
		}

	}

	private String getOrgUnitPathString(String groupName, boolean create) throws InternalErrorException, IOException {
		List<String> path = getOrgUnitPath(groupName, create);
		StringBuffer sb = new StringBuffer();
		for (String p: path)
			sb.append ('/').append(p);
		
		return sb.toString();
	}

	private List<String> getOrgUnitPath(String codiGrupPrimari, boolean create) throws InternalErrorException, IOException {
		try {
			Grup gi = getServer().getGroupInfo(codiGrupPrimari, getCodi());
			List<String> path ;
			if (gi .getCodiPare() != null)
				path = getOrgUnitPath(gi.getCodiPare(), create);
			else
				path = new LinkedList<String>();

			
			ExtensibleObject sourceObject = new GroupExtensibleObject(gi, getCodi(), getServer());
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GROUP) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    			{
		    				String name = (String) obj.getAttribute("name");
		    				if (name != null)
		    				{
		    					path.add(name);
		    					OrgUnit orgunit = getDirectory().orgunits().get(customerId, path).execute();
		    					if (orgunit == null && create)
		    					{
	    							updateGroup (path, obj);
		    					}
		    				}
		    			}
					}
				}
			}
			
			return path;
			
		} catch (UnknownGroupException e) {
			return new LinkedList<String>();
		}
	}

	private void updateGroup(List<String> path, ExtensibleObject obj) throws IOException {
		StringBuffer parentPath = new StringBuffer();
		StringBuffer currentPath = new StringBuffer();
		String pathTail = null;
		for (Iterator<String> it= path.iterator(); it.hasNext();)
		{
			String p = it.next ();
			currentPath.append('/').append(p);
			if (it.hasNext())
				parentPath.append('/').append(p);
			else
				pathTail = p;
		}
			
		if (parentPath.length() == 0)
			parentPath.append("/");
		OrgUnit orgunit = getDirectory().orgunits().get(customerId, path).execute();
		if (orgunit == null)
		{
			orgunit = new OrgUnit();
			orgunit.setDescription((String) obj.getAttribute("description"));
			orgunit.setName((String) obj.getAttribute("name"));
			orgunit.setParentOrgUnitPath(parentPath.toString());
			getDirectory().orgunits().insert(customerId, orgunit).execute();
		} else {
			orgunit.setDescription((String) obj.getAttribute("description"));
			orgunit.setName((String) obj.getAttribute("name"));
			orgunit.setOrgUnitPath(currentPath.toString());
			orgunit.setParentOrgUnitPath(parentPath.toString());
			getDirectory().orgunits().update(customerId, path, orgunit).execute();
		}
	}

	public void updateGroup(String name, Grup gi) throws InternalErrorException {
		ExtensibleObject sourceObject = new GroupExtensibleObject(gi, getCodi(), getServer());
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_GROUP) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateGroup (getOrgUnitPath(gi.getCodi(), true), obj);
					}
					else
					{
						List<String> path = getOrgUnitPath(gi.getCodi(),false);
						OrgUnit ou = getDirectory().orgunits()
							.get(customerId, path)
							.execute();
						if (ou != null)
							getDirectory().orgunits().delete(customerId, path);
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void removeUser(String account) throws InternalErrorException,
			InternalErrorException {
		try {
			disableUser(account);
		} catch (IOException e) {
			throw new InternalErrorException("Error disabling user "+account, e);
		}
	}

	private void disableUser(String account) throws IOException {
		String[] split = account.split("@");
		String accountName = split[0];
		String accountDomain = split.length > 1 ? split[1] : googleDomain;
		
		User u = getDirectory().users().get(accountName+"@"+accountDomain).execute();
		if (u != null)
		{
			u.setSuspended(true);
			getDirectory().users().update(accountName+"@"+accountDomain, u)
				.execute();
		}
			
	}

	public void updateUserPassword(String account, Password password,
			boolean mustchange) throws RemoteException, InternalErrorException {
		String[] split = account.split("@");
		String accountName = split[0];
		String accountDomain = split.length > 1 ? split[1] : googleDomain;
		
		try {
			User u = getDirectory().users().get(accountName+"@"+accountDomain).execute();
			if (u != null)
			{
				User u2 = new User();
				u2.setId(u.getId());
				u2.setHashFunction("SHA-1");
				u2.setPrimaryEmail(u.getPrimaryEmail());
				byte[] hash = MessageDigest.getInstance("SHA-1").digest(password.getPassword().getBytes("UTF-8"));
				u2.setPassword( base16 (hash));
				
				getDirectory().users().patch(accountName+"@"+accountDomain, u2)
					.execute();
			}
		} catch (NoSuchAlgorithmException e) {
			throw new InternalErrorException("Error updating password for "+account, e);
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException("Error updating password for "+account, e);
		} catch (IOException e) {
			throw new InternalErrorException("Error updating password for "+account, e);
		}
	}

	/**
	 * Retrieves a user.
	 * 
	 * @param user
	 *            The user you wish to retrieve.
	 * @return A UserEntry object of the retrieved user.
	 * @throws AppsForYourDomainException
	 *             If a Provisioning API specific occurs.
	 * @throws ServiceException
	 *             If a generic GData framework error occurs.
	 * @throws IOException
	 *             If an error occurs communicating with the GData service.
	 */
	private User retrieveUser(String user, String domini)
			throws InternalErrorException {

		log.info("Retrieving user '{}'.", user, null);
		try {

			return getDirectory().users().get(user+"@"+domini).execute();
		} catch (Exception e) {
			throw new InternalErrorException("retrieveUser (" + user + ")", e);
		}
	}

	private String base16(byte[] hash) throws UnsupportedEncodingException {
		return new String (Hex.encode(hash), "UTF-8");
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), objects);
	}

	public void updateUserAlias(String useKey, Usuari user)
			throws InternalErrorException {
		
	}

	public void removeUserAlias(String userKey) throws InternalErrorException {
		
	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		ExtensibleObject sourceObject = new AccountExtensibleObject(acc, getServer());
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals (SoffidObjectType.OBJECT_ACCOUNT) )
				{
					if (objectTranslator.evalCondition(sourceObject, mapping))
					{
		    			ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
		    			if (obj != null)
		    				updateGoogleUser(accountName, acc, null, obj);
					}
					else
					{
						disableUser(acc.getName());
					}
				}
			}
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUserPassword(String userName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException {
		updateUserPassword(userName, password, mustchange);
		
	}

	public boolean validateUserPassword(String userName, Password password)
			throws RemoteException, InternalErrorException {
		return false;
	}

	public void removeGroup(String groupName) throws RemoteException,
			InternalErrorException {
		// Nothing to do on this version
	}

	public void updateListAlias(LlistaCorreu llista)
			throws InternalErrorException {
		try {
			if (llista.getCodiDomini().equals (googleDomain) &&
					! llista.getCodiDomini().endsWith("."+googleDomain))
				return;
			
			String name = llista.getNom() + "@" + llista.getCodiDomini();
			if (llista.getLlistaLlistes() == null)
				llista.setLlistaLlistes("");
			if (llista.getLlistaUsuaris() == null)
				llista.setLlistaUsuaris("");
			String users = llista.getExplodedUsersList();
			if (users == null)
				users = "";
			if (llista.getLlistaExterns().trim().length() == 0 &&
					llista.getLlistaLlistes().trim().length() == 0 &&
					users.trim().length() == 0 )
			{
				removeListAlias(llista.getNom(), llista.getCodiDomini());
				return;
			}
			Group g = getDirectory().groups().get(llista.getNom()+"@"+llista.getCodiDomini()).execute();
			
			if (g == null) {
				boolean singleUser = llista.getLlistaExterns().trim().isEmpty() && 
						llista.getLlistaLlistes().trim().isEmpty() &&
						users.equals(llista.getLlistaUsuaris()) &&
						!users.trim().contains(",");
				String owner = singleUser ? getUserEmail (users.trim()): null;
				
				String aliasOwner = getAliasOwner(name);
				if (singleUser)
				{
					if (owner != null &&  owner.equals(aliasOwner) )
					{
						// Nothing to do
						return;
					}
					
					if (aliasOwner != null)
					{
						User u = getDirectory().users().get(aliasOwner).execute();
						for (Iterator<String> it = u.getAliases().iterator(); it.hasNext(); )
						{
							String alias = it.next();
							if (alias.equalsIgnoreCase(name))
								it.remove();
						}
						getDirectory().users().update(aliasOwner, u).execute();
					}
					if (owner != null && ! owner.equals (name))
					{
						User u = getDirectory().users().get(aliasOwner).execute();
						u.getAliases().add(name);
						getDirectory().users().update(aliasOwner, u).execute();
						return;
					}
					else
					{
						// Now create a normal list
					}
				}
				else if (aliasOwner != null)
				{
					User u = getDirectory().users().get(aliasOwner).execute();
					for (Iterator<String> it = u.getAliases().iterator(); it.hasNext(); )
					{
						String alias = it.next();
						if (alias.equalsIgnoreCase(name))
							it.remove();
					}
					getDirectory().users().update(aliasOwner, u).execute();
				}
				g = new Group ();
				g.setAdminCreated(true);
				g.setDescription(llista.getDescripcio());
				g.setName(llista.getNom());
				g.setEmail(name);
				g = getDirectory().groups().insert(g).execute();
			}
			setListAliasMembers(name, llista, users, g);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	String getUserEmail (String user) throws InternalErrorException, es.caib.seycon.ng.exception.UnknownUserException
	{
		Usuari u = getServer().getUserInfo(user, null);
		for (Account acc : getServer().getUserAccounts(u.getId(),
				getCodi()))
		{
			if (! acc.isDisabled())
				return acc.getName();
		}
		
		if (u.getDominiCorreu() != null)
			return u.getNomCurt()+"@"+u.getDominiCorreu();
		else
		{
			DadaUsuari email = getServer().getUserData(u.getId(), "EMAIL");
			if (email != null && email.getValorDada() != null)
				return email.getValorDada();
				
		}
		return null;
	}
	
	private String getAliasOwner(String email) throws IOException {
		Users users = getDirectory().users().list().setQuery("email="+email).execute();
		if (users.getUsers().size() > 0)
		{
			return users.getUsers().get(0).getPrimaryEmail();
		}
		else
			return null;
	}

	private void setListAliasMembers(String name, LlistaCorreu llista, String users, Group g)
			throws IOException, TimedOutException, InternalErrorException,
			es.caib.seycon.ng.exception.UnknownUserException {
		Members members = getDirectory().members().list(g.getId()).execute();

		Set<String> current = new HashSet<String>();
		for (Member member: members.getMembers())
		{
			current.add(member.getEmail());
		}
		Set<String> newMembers = new HashSet<String>();
		if (llista.getLlistaExterns().trim().length() > 0 )
			for (String extern : llista.getLlistaExterns().split("[ ,]+"))
				newMembers.add(extern.toLowerCase());

		if (llista.getLlistaLlistes().trim().length() > 0 )
			for (String extern : llista.getLlistaLlistes().split("[ ,]+"))
				newMembers.add(extern.toLowerCase());

		if (users.trim().length() > 0 )
			for (String user : users.split("[ ,]+")) {
				Usuari u = getServer().getUserInfo(user, null);
				if (u != null) {
					boolean found = false;
				
					for (Account acc : getServer().getUserAccounts(u.getId(),
							getCodi())) {
						newMembers.add(acc.getName().toLowerCase());
						found = true;
					}
					if (! found )
					{
						if (u.getDominiCorreu() != null)
							newMembers.add (u.getNomCurt()+"@"+u.getDominiCorreu().toLowerCase());
						else
						{
							DadaUsuari email = getServer().getUserData(u.getId(), "EMAIL");
							if (email != null && email.getValorDada() != null)
								newMembers.add (email.getValorDada().toLowerCase());
								
						}
					}
				}
			}

		// Adds new members
		for (String newMember : newMembers) {
			if (!current.contains(newMember)) {
				Member m = new Member();
				m.setEmail(newMember);
				m.setRole("MEMBER");
				getDirectory().members().insert(g.getId(), m).execute();
			} else {
				current.remove(newMember);
			}
		}

		// Removes old members
		for (String oldMember : current) {
			Member m = getDirectory().members().get(g.getId(), oldMember).execute();
			if (m !=  null)
				getDirectory().members().delete(g.getId(), m.getId()).execute();
		}
	}


	public void removeListAlias(String list, String domain)
			throws InternalErrorException {
		if (! domain.equals(domain) && 
				!domain.endsWith("."+googleDomain))
			return;

		try {
			Group g = getDirectory().groups().get(list+"@"+domain).execute();
			if (g != null)
				getDirectory().groups().delete(g.getId()).execute();
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

}


