package com.soffid.iam.sync.agent.googleapps;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;
import javax.xml.rpc.ServiceException;

import org.bouncycastle.asn1.ocsp.ServiceLocator;
import org.bouncycastle.util.encoders.Hex;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.DateTime;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.SecurityUtils;
import com.google.api.client.util.PemReader.Section;
import com.google.api.services.admin.directory.DirectoryScopes;
import com.google.api.services.cloudresourcemanager.CloudResourceManager;
import com.google.api.services.cloudresourcemanager.CloudResourceManagerScopes;
import com.google.api.services.cloudresourcemanager.model.GetIamPolicyRequest;
import com.google.api.services.cloudresourcemanager.model.GetPolicyOptions;
import com.google.api.services.cloudresourcemanager.model.ListProjectsResponse;
import com.google.api.services.cloudresourcemanager.model.Organization;
import com.google.api.services.cloudresourcemanager.model.Project;
import com.google.api.services.cloudresourcemanager.model.SearchOrganizationsRequest;
import com.google.api.services.cloudresourcemanager.model.SearchOrganizationsResponse;
import com.google.api.services.iam.v1.Iam;
import com.google.api.services.iam.v1.IamScopes;
import com.google.api.services.iam.v1.model.Binding;
import com.google.api.services.iam.v1.model.CreateServiceAccountKeyRequest;
import com.google.api.services.iam.v1.model.CreateServiceAccountRequest;
import com.google.api.services.iam.v1.model.DisableServiceAccountRequest;
import com.google.api.services.iam.v1.model.EnableServiceAccountRequest;
import com.google.api.services.iam.v1.model.ListRolesResponse;
import com.google.api.services.iam.v1.model.ListServiceAccountsResponse;
import com.google.api.services.iam.v1.model.Policy;
import com.google.api.services.iam.v1.model.ServiceAccount;
import com.google.api.services.iam.v1.model.ServiceAccountKey;
import com.google.api.services.iam.v1.model.SetIamPolicyRequest;
import com.google.api.services.iam.v2.model.GoogleIamV2Policy;
import com.google.api.services.iam.v2.model.GoogleIamV2PolicyRule;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Application;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.Domain;
import com.soffid.iam.api.DomainValue;
import com.soffid.iam.api.HostService;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.DomainService;
import com.soffid.iam.sync.ServerServiceLocator;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownGroupException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.TimedOutException;

public class GoogleCloudAgent extends es.caib.seycon.ng.sync.agent.Agent
		implements UserMgr, GroupMgr, ExtensibleObjectMgr, RoleMgr, ReconcileMgr2 {

	private static final String APPS_APPLICATION_NAME = "SOFFID-SYNCSERVER-1_0";// [company-id]-[app-name]-[app-version]

	private PrivateKey privateKey;
	private String accountId;

	private com.google.api.services.iam.v2.Iam getIam2() {
		return new com.google.api.services.iam.v2.Iam.Builder(httpTransport, jsonFactory, googleCredentialIam)
				.setApplicationName(APPS_APPLICATION_NAME).build();

	}

	private com.google.api.services.iam.v1.Iam getIam() {
		return new com.google.api.services.iam.v1.Iam.Builder(httpTransport, jsonFactory, googleCredentialIam)
				.setApplicationName(APPS_APPLICATION_NAME).build();

	}

	private CloudResourceManager getResourceManager() {
		return new CloudResourceManager.Builder(httpTransport, jsonFactory, googleCredentialIam)
				.setApplicationName(APPS_APPLICATION_NAME).build();

	}

	private NetHttpTransport httpTransport;

	private JacksonFactory jsonFactory;

	private String googleDomain;

	private Collection<ExtensibleObjectMapping> objectMappings;

	private ObjectTranslator objectTranslator;

	private GoogleCredential googleCredentialIam;

	/**
	 * Paràmetres [0] user Administrador [1] admin Password [2] dominiGoogle
	 * 
	 * @param params
	 */
	public GoogleCloudAgent() throws java.rmi.RemoteException {
	}

	public void init() throws Exception {
		super.init();

		httpTransport = GoogleNetHttpTransport.newTrustedTransport();
		jsonFactory = JacksonFactory.getDefaultInstance();

		this.accountId = getDispatcher().getParam1();

		try {
			String pk = new String(getDispatcher().getBlobParam(), "UTF-8").replaceAll("\\\\n", "\n");
			Section section = PemReader.readFirstSectionAndClose(new StringReader(pk), "PRIVATE KEY");
			if (section == null) {
				throw new IOException("Invalid PEM key data.");
			}
			byte[] bytes = section.getBase64DecodedBytes();
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
			KeyFactory keyFactory = SecurityUtils.getRsaKeyFactory();
			privateKey = keyFactory.generatePrivate(keySpec);
		} catch (Throwable t) {
			throw new InternalErrorException("Error parsing private key", t);
		}

		String[] perms;
		perms = new String[] { IamScopes.CLOUD_PLATFORM,
				CloudResourceManagerScopes.CLOUD_PLATFORM};

		googleCredentialIam = new GoogleCredential.Builder().setTransport(httpTransport).setJsonFactory(jsonFactory)
				.setServiceAccountId(accountId).setServiceAccountScopes(Arrays.asList(perms))
				.setServiceAccountPrivateKey(privateKey).build();

	}

	private boolean hasRoleMapping() {
		for (ExtensibleObjectMapping mapping : objectMappings) {
			if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
				return true;
		}
		return false;
	}

	public void updateUser(String account, Usuari user) throws RemoteException, InternalErrorException {
		updateUser(account, user.getFullName());
	}

	protected void updateGoogleAccount(String account, Account acc, ExtensibleObject obj)
			throws InternalErrorException {
		try {
			if (account.endsWith(".gserviceaccount.com")) {
				CloudResourceManager rm = getResourceManager();
				ServiceAccount serviceAccount = findServiceAccount(account);
	
				if (serviceAccount == null) { // USUARI NOU
					log.info("l'usuari {} no existeix a google, el creem", account, null);
					int i = account.indexOf("@");
					if (i < 0) 
						throw new InternalErrorException("Account must follow the pattern NAME@PROJECT.iam.gserviceaccount.com");
					String alias = account.substring(0, i);
					String domain = account.substring(i+1);
					i = domain.indexOf(".");
					if (i < 0) 
						throw new InternalErrorException("Account must follow the pattern NAME@PROJECT.iam.gserviceaccount.com");
					domain = domain.substring(0, i);
					// Donem d'alta a l'usuari en google
					byte b[] = new byte[18];
					new SecureRandom().nextBytes(b);
					serviceAccount = new ServiceAccount();
					serviceAccount.setDescription(acc.getDescription());
					serviceAccount.setDisplayName(account);
					CreateServiceAccountRequest createRequest = new CreateServiceAccountRequest();
					createRequest.setServiceAccount(serviceAccount);
					createRequest.setAccountId(alias);
					ServiceAccount response = getIam().projects().serviceAccounts().create(
							"projects/"+domain, createRequest).execute();
					if (! response.getEmail().equals(account)) {
						acc.setName(response.getEmail());
						new es.caib.seycon.ng.remote.RemoteServiceLocator()
						.getAccountService().updateAccount2(acc);
					}
					
					CreateServiceAccountKeyRequest ckr = new CreateServiceAccountKeyRequest();
					ServiceAccountKey key = getIam().projects().serviceAccounts().keys().create(
							response.getName(), 
							ckr ).execute();
					addKey(acc, key);
				} else if (serviceAccount.getDisabled() != null &&
						serviceAccount.getDisabled().booleanValue()) { // USUARI EXISTENT
					EnableServiceAccountRequest esar = new EnableServiceAccountRequest();
					getIam().projects().serviceAccounts().enable(account, esar).execute();
				}
			}	
			updateAccountRoles(acc);
		} catch (InternalErrorException e) {
			e.printStackTrace();
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(e.getMessage(), e);
		}

	}

	private void addKey(Account account, ServiceAccountKey key) throws InternalErrorException, IOException, AccountAlreadyExistsException {
		DataType md = new RemoteServiceLocator()
				.getAdditionalDataService()
				.findSystemDataType(getCodi(), "key");
		if (md == null) {
			md = new DataType();
			md.setName("key");
			md.setSystemName(getCodi());
			md.setType(TypeEnumeration.BINARY_TYPE);
			new RemoteServiceLocator().getAdditionalDataService().create(md);
		}
		String keyMaterial = key.getPrivateKeyData();
		account.getAttributes().put("key", keyMaterial.getBytes(StandardCharsets.UTF_8));
		new es.caib.seycon.ng.remote.RemoteServiceLocator().getAccountService().updateAccount2(account);
//		new es.caib.seycon.ng.remote.RemoteServiceLocator().getAccountService()
//			.setAccountSshPrivateKey(account, keyMaterial);
	}

	private void updateAccountRoles(Account acc)
			throws IOException, InternalErrorException {
//		fetchRoles();
		log.info("Setting permissions for " + acc.getName());
		for (ExtensibleObjectMapping mapping : objectMappings) {
			if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE)) {
				Collection<RolGrant> roles = getServer().getAccountRoles(acc.getName(), acc.getDispatcher());
				Collection<RolGrant> existings = getAccountGrants(acc.getName());

				l1: for (Iterator<RolGrant> it = roles.iterator(); it.hasNext();) {
					RolGrant role = it.next();
					for (Iterator<RolGrant> it2 = existings.iterator(); it2.hasNext();) {
						RolGrant existing = it2.next();
						if (existing.getRolName().equals(role.getRolName()) &&
								existing.getDomainValue().equals(role.getDomainValue())) {
							// Match
							it.remove();
							it2.remove();
							continue l1;
						}
					}
					grant(role);
				}
				
				for (RolGrant existing: existings)
					revoke(existing);
			}
		}
	}

	private void grant(RolGrant role) throws IOException {
		CloudResourceManager rm = getResourceManager();
		GetIamPolicyRequest r = new GetIamPolicyRequest();
		GetPolicyOptions gpo = new GetPolicyOptions();
		gpo.setRequestedPolicyVersion(1);
		r.setOptions(gpo );

		String name = role.getOwnerAccountName().endsWith("gserviceaccount.com") ?
				"serviceAccount:"+role.getOwnerAccountName() :
				"user:"+role.getOwnerAccountName();
		
		if (role.getDomainValue().startsWith("projects/")) {
			String projectId = role.getDomainValue().substring(9);
			com.google.api.services.cloudresourcemanager.model.Policy policy = 
					rm.projects().getIamPolicy(projectId, r ).execute();
			if (policy != null) {
				boolean found = false;
				for (com.google.api.services.cloudresourcemanager.model.Binding binding: policy.getBindings()) {
					if (binding.getRole().equals(role.getRolName()) &&
							binding.getCondition() == null) {
						binding.getMembers().add(name);
						found = true;
						break;
					}
				}
				if (!found) {
					com.google.api.services.cloudresourcemanager.model.Binding binding =
							new com.google.api.services.cloudresourcemanager.model.Binding();
					binding.setRole(role.getRolName());
					binding.setMembers(Arrays.asList(name));
					policy.getBindings().add(binding);
				}
				com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest req = 
						new com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest();
				req.setPolicy(policy);
				rm.projects().setIamPolicy(projectId, req).execute();
			}
		}
		if (role.getDomainValue().startsWith("organization/")) {
			String orgId = role.getDomainValue();
			com.google.api.services.cloudresourcemanager.model.Policy policy = 
					rm.organizations().getIamPolicy(orgId, r ).execute();
			if (policy != null) {
				boolean found = false;
				for (com.google.api.services.cloudresourcemanager.model.Binding binding: policy.getBindings()) {
					if (binding.getRole().equals(role.getRolName()) &&
							binding.getCondition() == null) {
						binding.getMembers().add(name);
						found = true;
						break;
					}
				}
				if (!found) {
					com.google.api.services.cloudresourcemanager.model.Binding binding =
							new com.google.api.services.cloudresourcemanager.model.Binding();
					binding.setRole(role.getRolName());
					binding.setMembers(Arrays.asList(name));
					policy.getBindings().add(binding);
				}
				com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest req = 
						new com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest();
				req.setPolicy(policy);
				rm.projects().setIamPolicy(orgId, req);
			}
		}
	}

	private void revoke(RolGrant role) throws IOException {
		CloudResourceManager rm = getResourceManager();
		GetIamPolicyRequest r = new GetIamPolicyRequest();
		GetPolicyOptions gpo = new GetPolicyOptions();
		gpo.setRequestedPolicyVersion(1);
		r.setOptions(gpo );

		String name = role.getOwnerAccountName().endsWith("gserviceaccount.com") ?
				"serviceAccount:"+role.getOwnerAccountName() :
				"user:"+role.getOwnerAccountName();
		String projectId = null;
		if (role.getDomainValue().startsWith("projects/")) 
			projectId = role.getDomainValue().substring(9);
		if (role.getDomainValue().startsWith("project/")) 
			projectId = role.getDomainValue().substring(8);
		if (projectId != null) {
				com.google.api.services.cloudresourcemanager.model.Policy policy = 
					rm.projects().getIamPolicy(projectId, r ).execute();
			if (policy != null) {
				boolean found = false;
				for (Iterator<com.google.api.services.cloudresourcemanager.model.Binding> it =
						policy.getBindings().iterator();
							it.hasNext();) {
						com.google.api.services.cloudresourcemanager.model.Binding binding = it.next();
					if (binding.getRole().equals(role.getRolName()) &&
							binding.getCondition() == null) {
						binding.getMembers().remove(name);
						if (binding.getMembers().isEmpty())
							it.remove();
					}
				}
				com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest req = 
						new com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest();
				req.setPolicy(policy);
				//policy.setEtag(Long.toString(System.currentTimeMillis()));
				req.setUpdateMask("bindings");
				rm.projects().setIamPolicy(projectId, req).execute();
			}
		}
		if (role.getDomainValue().startsWith("organizations/")) {
			String orgId = role.getDomainValue();
			com.google.api.services.cloudresourcemanager.model.Policy policy = 
					rm.organizations().getIamPolicy(orgId, r ).execute();
			if (policy != null) {
				boolean found = false;
				for (Iterator<com.google.api.services.cloudresourcemanager.model.Binding> it =
					policy.getBindings().iterator();
						it.hasNext();) {
					com.google.api.services.cloudresourcemanager.model.Binding binding = it.next();
					if (binding.getRole().equals(role.getRolName()) &&
							binding.getCondition() == null) {
						binding.getMembers().remove(name);
						if (binding.getMembers().isEmpty()) 
							it.remove();
					}
				}
				com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest req = 
						new com.google.api.services.cloudresourcemanager.model.SetIamPolicyRequest();
				req.setPolicy(policy);
				req.setUpdateMask("bindings");
				rm.organizations().setIamPolicy(orgId, req).execute();
			}
		}
	}

	protected ServiceAccount findServiceAccount(String account)
			throws InternalErrorException {
		try {
			CloudResourceManager rm = getResourceManager();
			for (ListProjectsResponse projects = null; projects == null || projects.getNextPageToken() != null;) {
				projects = getResourceManager().projects().list()
						.setPageToken(projects == null ? null : projects.getNextPageToken()).execute();
				for (Project project : projects.getProjects()) {
					if ("ACTIVE".equals(project.getLifecycleState())) {
						ListServiceAccountsResponse lsa = null;
						try {
							do {
								lsa = getIam().projects().serviceAccounts().list("projects/" + project.getProjectId())
										.setPageToken(lsa == null ? null : lsa.getNextPageToken()).execute();
								if (lsa.getAccounts() != null) {
									for (ServiceAccount user : lsa.getAccounts()) {
										if (user.getEmail().equals(account)) {
											return user;
										}
									}
								}
							} while (lsa.getNextPageToken() != null);
						} catch (GoogleJsonResponseException e) {
							if (e.getStatusCode() != 404) // Not Found
								throw e;
						}
					}
				}
			}
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(e.getMessage(), e);
		}

	}

	protected ExtensibleObject findServiceAccount(String account, ExtensibleObjectMapping mapping)
			throws InternalErrorException {
		try {
			ServiceAccount sa = findServiceAccount(account);
			if (sa != null) {
				ExtensibleObject obj = new ExtensibleObject();
				obj.setObjectType(mapping.getSystemObject());
				for (String key : sa.keySet()) {
					copyAttribute(obj, sa, key);
				}
				return obj;
			} else {
				ExtensibleObject obj = new ExtensibleObject();
				obj.setObjectType(mapping.getSystemObject());
				obj.setAttribute("email", account);
				obj.setAttribute("description", account);
				return obj;
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(e.getMessage(), e);
		}

	}

	private Object copyAttribute(Object src) {
		if (src instanceof Map) {
			HashMap<String, Object> t = new HashMap<String, Object>();
			Map<String, Object> srcMap = (Map<String, Object>) src;
			for (String key2 : srcMap.keySet()) {
				copyAttribute(t, srcMap, key2);
			}
			return t;
		} else if (src instanceof Collection) {
			LinkedList<Object> t = new LinkedList<Object>();
			Collection<Object> srcMap = (Collection<Object>) src;
			for (Object o : srcMap) {
				t.add(copyAttribute(o));
			}
			return t;
		} else if (src instanceof DateTime) {
			return new Date(((DateTime) src).getValue());
		} else {
			return src;
		}

	}

	private void copyAttribute(Map<String, Object> target, Map<String, Object> source, String key) {
		Object src = source.get(key);

		if (src instanceof Map) {
			Map<String, Object> t = (Map<String, Object>) target.get(key);
			if (t == null) {
				t = new HashMap<String, Object>();
				target.put(key, t);
			}
			Map<String, Object> srcMap = (Map<String, Object>) src;
			for (String key2 : srcMap.keySet()) {
				copyAttribute(t, srcMap, key2);
			}
		} else if (src instanceof Collection) {
			Collection<Object> t = (Collection<Object>) target.get(key);
			if (t == null) {
				t = new LinkedList<Object>();
				target.put(key, t);
			}
			Collection<Object> srcMap = (Collection<Object>) src;
			for (Object o : srcMap) {
				t.add(copyAttribute(o));
			}
		} else {
			target.put(key, copyAttribute(src));
		}
	}

	public void removeUser(String account) throws InternalErrorException, InternalErrorException {
		try {
			disableUser(account);
			Collection<RolGrant> existings = getAccountGrants(account);
			for (RolGrant existing: existings)
				revoke(existing);
			Account acc = getServer().getAccountInfo(account, getCodi());
			if (acc == null || acc.getStatus() == AccountStatus.REMOVED)
				removeGCPUser(account);
		} catch (IOException e) {
			throw new InternalErrorException("Error disabling user " + account, e);
		}
	}

	private void disableUser(String account) throws IOException, InternalErrorException {
		if (account.endsWith("gserviceaccount.com")) {
			ServiceAccount u = findServiceAccount(account);
			if (u != null && ! Boolean.TRUE.equals(u.getDisabled())) {
				DisableServiceAccountRequest esar = new DisableServiceAccountRequest();
				log.info("Disabling "+u.getName());
				getIam().projects().serviceAccounts()
					.disable(u.getName(), 
							esar).execute();
			}
		}
	}

	private void removeGCPUser(String account) throws IOException, InternalErrorException {
		if (account.endsWith("gserviceaccount.com")) {
			ServiceAccount u = findServiceAccount(account);
			if (u != null && ! Boolean.TRUE.equals(u.getDisabled())) {
				DisableServiceAccountRequest esar = new DisableServiceAccountRequest();
				log.info("Disabling "+u.getName());
				getIam().projects().serviceAccounts()
						.disable(u.getName(), 
							esar).execute();
			}
			if (u != null)
				getIam().projects().serviceAccounts()
					.delete(u.getName()).execute();
		}
	}

	public void updateUserPassword(String account, Password password, boolean mustchange)
			throws RemoteException, InternalErrorException {
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), objects);
	}

	public void updateUserAlias(String useKey, Usuari user) throws InternalErrorException {

	}

	public void removeUserAlias(String userKey) throws InternalErrorException {

	}

	public void updateUser(String accountName, String description) throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		if (acc == null) {
			acc = new Account();
			acc.setName(accountName);
			acc.setDescription(description);
			acc.setDisabled(true);
			acc.setStatus(AccountStatus.REMOVED);
		}
		ExtensibleObject sourceObject = new AccountExtensibleObject(acc, getServer());
		try {
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT)) {
					if (objectTranslator.evalCondition(sourceObject, mapping)) {
						ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
						if (obj != null)
							updateGoogleAccount(accountName, acc, sourceObject);
					} else {
						disableUser(acc.getName());
					}
				}
			}
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUserPassword(String userName, Usuari userData, Password password, boolean mustchange)
			throws RemoteException, InternalErrorException {
		updateUserPassword(userName, password, mustchange);

	}

	public boolean validateUserPassword(String userName, Password password)
			throws RemoteException, InternalErrorException {
		return false;
	}

	public void removeGroup(String groupName) throws RemoteException, InternalErrorException {
		// Nothing to do on this version
	}

	public void updateListAlias(LlistaCorreu llista) throws InternalErrorException {
	}

	private void removeAlias(String name, String aliasOwner) throws IOException {
	}


	public void removeRole(String role, String system) throws RemoteException, InternalErrorException {
	}

	public void updateRole(Rol role) throws RemoteException, InternalErrorException {

	}


	public List<RolGrant> getAccountGrants(String account) throws RemoteException, InternalErrorException {
		List<RolGrant> grants = new LinkedList<RolGrant>();
		try {
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE)) {
					fetchRoles();
					
					GetIamPolicyRequest r = new GetIamPolicyRequest();
					GetPolicyOptions gpo = new GetPolicyOptions();
					gpo.setRequestedPolicyVersion(1);
					r.setOptions(gpo );

					final CloudResourceManager rm = getResourceManager();
					for (ListProjectsResponse projects = null; projects == null || projects.getNextPageToken() != null;) {
						projects = rm.projects().list()
								.setPageToken(projects == null ? null : projects.getNextPageToken()).execute();
						for (Project project : projects.getProjects()) {
							com.google.api.services.cloudresourcemanager.model.Policy policy = 
									rm.projects().getIamPolicy(project.getProjectId(), r ).execute();
							grants.addAll(filterPermissions(policy, account, "projects/"+project.getProjectId()));
						}
					}
					SearchOrganizationsRequest sor = new SearchOrganizationsRequest();
					sor.setFilter("");
					for (SearchOrganizationsResponse organizations = null; organizations == null
							|| organizations.getNextPageToken() != null;) {
						if (organizations != null)
							sor.setPageToken(organizations.getNextPageToken());
						organizations = getResourceManager().organizations().search(sor).execute();
						if (organizations.getOrganizations() != null) {
							for (Organization organization : organizations.getOrganizations()) {
								com.google.api.services.cloudresourcemanager.model.Policy policy = 
										rm.organizations().getIamPolicy(organization.getName(), r ).execute();
								grants.addAll(filterPermissions(policy, account, organization.getName()));
							}
						}
					}
				}
			}
		} catch (IOException e) {
			throw new RemoteException("Error invoking Google API", e);
		}
		return grants;
	}

	private Collection<RolGrant> filterPermissions(
			com.google.api.services.cloudresourcemanager.model.Policy policy, String account, String domainValue) {
		Collection<RolGrant> l = new LinkedList<>();
		if (policy != null && policy.getBindings() != null) {
			for (com.google.api.services.cloudresourcemanager.model.Binding binding: policy.getBindings()) {
				for (String member: binding.getMembers()) {
					if (member.equals("serviceAccount:"+account) ||
							member.equals("user:"+account))
					{
						RolGrant rg = new RolGrant();
						rg.setRolName(binding.getRole());
						rg.setDomainValue(domainValue);
						rg.setOwnerAccountName(account);
						l.add(rg);
					}
				}
			}
		}
		return l;
	}

	public Account getAccountInfo(String account) throws RemoteException, InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT)) {
					ExtensibleObject obj = findServiceAccount(account, mapping);
					if (obj != null) {
						ExtensibleObject src = objectTranslator.parseInputObject(obj, mapping);
						if (obj != null) {
							Account a = new ValueObjectMapper().parseAccount(src);
							a.setName(account);
							return a;
						}
					}
				}
			}
			return null;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public List<String> getAccountsList() throws RemoteException, InternalErrorException {
		HashSet<String> r = new HashSet<String>();

		GetIamPolicyRequest pr = new GetIamPolicyRequest();
		GetPolicyOptions gpo = new GetPolicyOptions();
		gpo.setRequestedPolicyVersion(1);
		pr.setOptions(gpo );

		try {
			CloudResourceManager rm = getResourceManager();
			for (ListProjectsResponse projects = null; projects == null || projects.getNextPageToken() != null;) {
				projects = getResourceManager().projects().list()
						.setPageToken(projects == null ? null : projects.getNextPageToken()).execute();
				for (Project project : projects.getProjects()) {
					if ("ACTIVE".equals(project.getLifecycleState())) {
						ListServiceAccountsResponse lsa = null;
						try {
							do {
								lsa = getIam().projects().serviceAccounts().list("projects/" + project.getProjectId())
										.setPageToken(lsa == null ? null : lsa.getNextPageToken()).execute();
								if (lsa.getAccounts() != null) {
									for (ServiceAccount user : lsa.getAccounts()) {
										r.add(user.getEmail());
									}
								}
							} while (lsa.getNextPageToken() != null);
						} catch (GoogleJsonResponseException e) {
							if (e.getStatusCode() != 404) // Not Found
								throw e;
						}
						try {
							com.google.api.services.cloudresourcemanager.model.Policy policy = 
									rm.projects().getIamPolicy(project.getProjectId(), pr ).execute();
							addPolicyMembers(r, policy);
						} catch (Exception e) {
						}
					}
				}
			}
			SearchOrganizationsRequest sor = new SearchOrganizationsRequest();
			sor.setFilter("");
			for (SearchOrganizationsResponse organizations = null;
					organizations == null || organizations.getNextPageToken() != null; )
			{
				if (organizations != null)
					sor.setPageToken(organizations.getNextPageToken());
				organizations = rm.organizations().search(sor).execute();
				for (Organization organization: organizations.getOrganizations()) {
					try {
						com.google.api.services.cloudresourcemanager.model.Policy policy = 
								rm.organizations().getIamPolicy(organization.getName(), pr ).execute();
						addPolicyMembers(r, policy);
					} catch (Exception e) {
					}
				}
			}
		} catch (IOException e) {
			throw new InternalErrorException("Error invoking google apps", e);
		}

		return new LinkedList<>(r);
	}

	protected void addPolicyMembers(HashSet<String> r,
			com.google.api.services.cloudresourcemanager.model.Policy policy) {
		if (policy != null && policy.getBindings() != null)
			for (com.google.api.services.cloudresourcemanager.model.Binding binding: 
				policy.getBindings())
				if (binding.getMembers() != null)
					for (String member: binding.getMembers())
						if (member.startsWith("user:"))
							r.add(member.substring(5));
						else if (member.startsWith("serviceAccount:"))
							r.add(member.substring(15));
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException, InternalErrorException {
		try {

			com.google.api.services.iam.v1.model.Role r = iamRolesByName.get(roleName);
			if (r != null) {
				Rol role = new Rol();
				role.setNom(r.getName());
				role.setDescripcio(r.getDescription());
				role.setDomini("Projects");
				return role;
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public List<String> getRolesList() throws RemoteException, InternalErrorException {
		if (hasRoleMapping()) {
			try {
				fetchProjects();
			} catch (IOException e) {
				throw new InternalErrorException("Error fetching projects", e);
			}
			fetchRoles();
		}

		return new LinkedList<String>(iamRolesByName.keySet());
	}

	private void fetchProjects() throws InternalErrorException, IOException {
		Application app = new RemoteServiceLocator().getApplicationService()
				.findApplicationByApplicationName(getCodi());
		if (app == null) {
			app = new Application();
			app.setName(getDispatcher().getCodi());
			app.setDescription(getDispatcher().getDescription());
			app = new RemoteServiceLocator().getApplicationService().create(app);
		}
		for (ListProjectsResponse projects = null; projects == null || projects.getNextPageToken() != null;) {
			projects = getResourceManager().projects().list()
					.setPageToken(projects == null ? null : projects.getNextPageToken()).execute();
			for (Project project : projects.getProjects()) {
				System.out.println("Project " + project.getName() + " " + project.getProjectId());
				addProject("projects/" + project.getProjectId(), project.getName());
			}
		}
		SearchOrganizationsRequest sor = new SearchOrganizationsRequest();
		sor.setFilter("");
		for (SearchOrganizationsResponse organizations = null; organizations == null
				|| organizations.getNextPageToken() != null;) {
			if (organizations != null)
				sor.setPageToken(organizations.getNextPageToken());
			organizations = getResourceManager().organizations().search(sor).execute();
			if (organizations.getOrganizations() != null) {
				for (Organization organization : organizations.getOrganizations()) {
					addProject(organization.getName(), organization.getDisplayName());
				}
			}
		}
	}

	private void addProject(String name, String displayName) throws InternalErrorException {
		DomainService ds = com.soffid.iam.ServiceLocator.instance().getDomainService();
		Domain domain = ds.findApplicationDomainByDomianNameAndApplicationName("Projects", getCodi());
		if (domain == null) {
			domain = new Domain();
			domain.setName("Projects");
			domain.setDescription("Projects");
			domain.setExternalCode(getCodi());
			ds.create(domain);
		}
		if (ds.findApplicationDomainValueByDomainNameAndDomainApplicationNameAndValue("Projects", getCodi(),
				name) == null) {
			DomainValue dv = new DomainValue();
			dv.setDomainName("Projects");
			dv.setExternalCodeDomain(getCodi());
			dv.setDescription(displayName);
			dv.setValue(name);
			ds.create(dv);
		}
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		for (ExtensibleObjectMapping mapping : objectMappings) {
			if (mapping.getSoffidObject().equals(type)) {
				ExtensibleObject obj = findServiceAccount(object1, mapping);
				if (obj != null) {
					return obj;
				}
			}
		}
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		for (ExtensibleObjectMapping mapping : objectMappings) {
			if (mapping.getSoffidObject().equals(type)) {
				ExtensibleObject obj = findServiceAccount(object1, mapping);
				if (obj != null) {
					ExtensibleObject src = objectTranslator.parseInputObject(obj, mapping);
					if (src != null) {
						return src;
					}
				}
			}
		}
		return null;
	}

	long lastUpdate = 0;
	private Map<String, com.google.api.services.iam.v1.model.Role> iamRolesByName = new HashMap<>();

	protected void fetchRoles() throws InternalErrorException {
		if (lastUpdate < System.currentTimeMillis() - 1000 * 60 * 5) { // 5 minutes cache
			iamRolesByName.clear();
			ListRolesResponse lpresp = null;
			do {
				try {
					lpresp = getIam().roles().list().setPageToken(lpresp == null ? null : lpresp.getNextPageToken())
							.execute();
				} catch (IOException e) {
					throw new InternalErrorException("Error invoking google apps", e);
				}
				if (lpresp.getRoles() != null) {
					for (com.google.api.services.iam.v1.model.Role role : lpresp.getRoles()) {
						iamRolesByName.put(role.getName(), role);
					}

				}
			} while (lpresp.getNextPageToken() != null);
		}
	}

	@Override
	public List<HostService> getHostServices() throws RemoteException, InternalErrorException {
		return null;
	}

	@Override
	public void removeExtensibleObject(ExtensibleObject arg0) throws RemoteException, InternalErrorException {
	}

	@Override
	public void updateExtensibleObject(ExtensibleObject arg0) throws RemoteException, InternalErrorException {
	}

	@Override
	public void updateGroup(String arg0, Grup arg1) throws RemoteException, InternalErrorException {
	}


}
