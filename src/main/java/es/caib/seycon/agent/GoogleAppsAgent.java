package es.caib.seycon.agent;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gdata.client.appsforyourdomain.AppsForYourDomainQuery;
import com.google.gdata.client.appsforyourdomain.AppsGroupsService;
import com.google.gdata.client.appsforyourdomain.AppsPropertyService;
import com.google.gdata.client.appsforyourdomain.NicknameService;
import com.google.gdata.client.appsforyourdomain.UserService;
import com.google.gdata.data.appsforyourdomain.AppsForYourDomainErrorCode;
import com.google.gdata.data.appsforyourdomain.AppsForYourDomainException;
import com.google.gdata.data.appsforyourdomain.Login;
import com.google.gdata.data.appsforyourdomain.Name;
import com.google.gdata.data.appsforyourdomain.Nickname;
import com.google.gdata.data.appsforyourdomain.Quota;
import com.google.gdata.data.appsforyourdomain.generic.GenericEntry;
import com.google.gdata.data.appsforyourdomain.generic.GenericFeed;
import com.google.gdata.data.appsforyourdomain.provisioning.NicknameEntry;
import com.google.gdata.data.appsforyourdomain.provisioning.NicknameFeed;
import com.google.gdata.data.appsforyourdomain.provisioning.UserEntry;
import com.google.gdata.util.AuthenticationException;
import com.google.gdata.util.ServiceException;

import es.caib.seycon.Agent;
import es.caib.seycon.GroupInfo;
import es.caib.seycon.InternalErrorException;
import es.caib.seycon.InternalErrorException2;
import es.caib.seycon.MailAliasMgr;
import es.caib.seycon.Password;
import es.caib.seycon.RoleInfo;
import es.caib.seycon.RoleMgr;
import es.caib.seycon.UnknownGroupException;
import es.caib.seycon.UnknownRoleException;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.UserInfo;
import es.caib.seycon.UserMgr;
import es.caib.seycon.agent.googleapps.Constants;
import es.caib.seycon.agent.googleapps.GmailSettingsService;

public class GoogleAppsAgent extends Agent implements UserMgr, MailAliasMgr, RoleMgr {

	private UserService userService;
	private AppsGroupsService groupService;
	private GmailSettingsService gmailSettingsService;
	private NicknameService nicknameService;
	
	
	// Contants per a les bústies compartides
	private final String GRUP_BUSTIES_COMPARTIDES="Bústies Compartides";
	private final String DESCRIPCIO_GRUP_BUSTIES_COMPARTIDES="Usuaris de Bústies Compartides";
	

	private static final String APPS_FEEDS_URL_BASE = "https://apps-apis.google.com/a/feeds/";
	protected static final String SERVICE_VERSION = "2.0";
	private static final String APPS_APPLICATION_NAME = "CAIB-GoogleAppsAgent-1_0";//[company-id]-[app-name]-[app-version]
	
	// Propietats de les Unitats Organitzatives
	private static class OrgUnitProperty {
		public final static String NAME = "name", 
				DESCRIPTION = "description",
				PARENT_ORG_UNIT_PATH = "parentOrgUnitPath",
				BLOCK_INHERTANCE = "blockInheritance",
				USERS_TO_MOVE = "usersToMove",
				ORG_UNIT_PATH="orgUnitPath"; //ruta actual (usuari)
	}	
	
	
	// Propietats dels usuaris de les llistes de correu (grups a google)
	//memberType=User, memberId=seguretat1@dgtic.caib.es, directMember=true
	private static class OrgGroupMember {
		public final static String MEMBER_TYPE = "memberType", MEMBER_ID = "memberId",
				DIRECT_MEMBER = "directMember";
	}
	
	
	private static final String PAQUETE_GOOGLE = "com.google.gdata";
	
	private String adminUser;
	private Password adminPass;
	private final String dominiGoogle;
	private AppsPropertyService appsPropertyService;
	
	private String customerId = null; // L'obtenim en el mètod init()

	/**
	 * Paràmetres
	 * [0] user Administrador 
	 * [1] admin Password 
	 * [2] dominiGoogle
	 * 
	 * @param params
	 */
	public GoogleAppsAgent(String[] params) throws java.rmi.RemoteException {
		super(params);
		this.adminUser = params[0];
		this.adminPass =  Password.decode(params[1]);
		this.dominiGoogle = params[2];
	}


	public void init() throws InternalErrorException {
		super.init();

		// comprovem el domini
		if (dominiGoogle == null || (dominiGoogle != null && "".equals(dominiGoogle.trim())))
			throw new InternalErrorException(
					"És necessari especificar el domini de correu");

		try {
			String adminPassword = adminPass.getPassword();
			String adminEmail = adminUser+"@"+dominiGoogle;
			

			userService = new UserService(
					"gdata-googleAppsAgent-AppsForYourDomain-UserService");
			userService.setUserCredentials(adminEmail, adminPassword);

			groupService = new AppsGroupsService(adminEmail, adminPassword,
					dominiGoogle,
					"gdata-googleAppsAgent-AppsForYourDomain-AppsGroupService");
			
			nicknameService = new NicknameService(
					"gdata-googleAppsAgent-AppsForYourDomain-NicknameService");
			nicknameService.setUserCredentials(adminEmail, adminPassword);			

			gmailSettingsService = new GmailSettingsService(
					"gdata-googleAppsAgent-AppsForYourDomain-GmailSettingsService",
					dominiGoogle, adminEmail, adminPassword);
			
			appsPropertyService = new AppsGroupsService(dominiGoogle, APPS_APPLICATION_NAME);
			appsPropertyService.setUserCredentials(adminEmail, adminPassword);
			
			try {
				customerId = retrieveCustomerId(dominiGoogle);
			} catch (Throwable th) {
				throw new InternalErrorException2(
						"No s'ha pogut obtindre el customerId ", th,
						PAQUETE_GOOGLE);
			}
			
			if (customerId == null
					|| (customerId != null && "".equals(customerId.trim())))
				throw new InternalErrorException(
						"No s'ha obtungut valor per a customerId");
		} catch (InternalErrorException ie) {
			throw ie;
		} catch (AuthenticationException ex) {
			log.warn("Error d'autenticació ", ex);
			throw new InternalErrorException2("Error d'autenticació ", ex,
					PAQUETE_GOOGLE);
		}

	}
	
	/**
	 * Obtenim la ruta del grup des del arrel (sense incloure el grup actual)
	 * @param codiGrup
	 * @return
	 * @throws InternalErrorException
	 * @throws RemoteException
	 * @throws UnknownGroupException
	 */
	private Map <String, Object> obteRutaPareGrup (GroupInfo gi) throws InternalErrorException, RemoteException, UnknownGroupException{
		
		String ruta = ""; //no incloen em grup actual (!!)
		
		String grupActual = gi.Name;
		
		Map <String, Object> infoGrups = new HashMap<String, Object>();

		while (gi!=null && gi.parent != null) {
			if (gi.parent !=null && !"".equals(gi.parent.trim()) ) {
				grupActual = gi.parent;
				ruta = grupActual + "/" + ruta;
				gi = getServer().GetGroupInfo(grupActual);
				infoGrups.put(grupActual, gi);
			}
		} 
			
		infoGrups.put("ruta", ruta);
		
		// la ruta pot ésser "" o "pares/"
		return infoGrups; 
		
	}
	
	private boolean esDominiCorrecteUsuari(String domini) {
		if (domini == null || "nul".equals(domini)) return false;

		// Ja se ha comprovat que nos iga nul
		return (dominiGoogle.equals(domini));
		
	}
	

	public void UpdateUser(String user) throws RemoteException,
			InternalErrorException {

		boolean active;

		UserInfo ui = null;
		RoleInfo roles[] = null;

		try {
			// Obtener los datos del usuario
			try {
				ui = getServer().GetUserInfo(user);
				// Obtenim els rols (bústies compartides)
				roles = getServer().GetUserRoles(user, getName()); 
				active = ui.active;
			} catch (UnknownUserException e)  {
				active = false;
			}
			
			// Mirem si hem d'ignorar l'usuari (el seu domini no és vàlid)
			if (ui==null || !esDominiCorrecteUsuari(ui.MailDomain)) {
				if (ui != null)
					log.info("UpdateUser {}: El domini de correu '{}' s'ignora",
							user, (ui != null ? ui.MailDomain : "nulo"));

				// Si abans existia, es posarà com a inactiu
				active = false; 
			}
			// En principi no hauria d'estar basat en rols (rol = bústia compartida)
			if (getRoleBased() && active && (roles==null || roles.length == 0) ) {
				active = false;
				log.info("UpdateUser {}: Setting active=false (active and roles.length=0) and getRoleBased",
						user, null);
			}

			if (active) { // si és actiu ui != null 
				// Mirem si ja existeix l'usuari a google

				// Només admitim codis de dominis específics (es valida abans)
				String dominiUsuari = ui.MailDomain;
				UserEntry usuariEntry = retrieveUser(user, dominiUsuari);
				
				String llinatges = ui.FirstFamilyName + (
						(ui.SecondFamilyName!=null && !"".equals(ui.SecondFamilyName))?(" "+ui.SecondFamilyName):"");
				
				if (usuariEntry == null) { // USUARI NOU
					log.info("l'usuari {} no existeix a google, el creem", user, null);
					// Donem d'alta a l'usuari en google
					//TODO: Només podran fer login des de la nostra pàgina, correcte?
					String password = generateRandomUserPassword(); 
					usuariEntry = createUser(ui.User, ui.Name, llinatges, password, null, null, dominiUsuari);
					
					// Li atorguem nomcurt i li fem el send-as
					if (ui.ShortName != null) { // És únic a nivell de seu..
						NicknameEntry nick = retrieveNickname(ui.ShortName,
								dominiUsuari);
						if (nick != null) {
							Login login = nick.getLogin();
							if (login != null
									&& !login.getUserName().equalsIgnoreCase(
											user)) {
								throw new InternalErrorException(
										"Ja existeix un altre usuari amb el mateix nomcurt "
												+ (login != null ? login
														.getUserName() : ""));
							}
						} else {
							// No existeix el nick, s'ha de crear
							// Comprovem abans que no existisca com a grup de google
							// (llista de correu).. perquè sinó dóna error al crear el nick
							try {							
								groupService.retrieveGroup(ui.ShortName);
							} catch (AppsForYourDomainException e) {
								// NO EXISTEIX: EL CREEM
								if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode())) {
									// Correcte
								} else { //altre tipus d'excepció (if possible)
									String msgError = 
											"Error cercant si existeix "
													+ ui.ShortName
													+ " com a grup a google "+e.getMessage();
									log.warn(msgError, e);
									throw new InternalErrorException2(msgError, e);
								}
							}
							
							nick = createNickname(user, ui.ShortName,
									dominiUsuari);
							Nickname n = nick.getNickname();
							Login login = nick.getLogin();
							log.info("Creat nickname {} per a usuari {}",
									n != null ? n.getName() : ui.ShortName,
									login != null ? login.getUserName() : user);
						}
						
						/*try {							
							
							groupService.retrieveGroup(ui.ShortName);
						} catch (AppsForYourDomainException e) {
							// NO EXISTEIX: EL CREEM
							if (e.getErrorCode() == AppsForYourDomainErrorCode.EntityDoesNotExist) {
								// Hem de crear el grup a google (no existeix encara)
								try {
									log.info(
											"Creant llista de correu (grup a google) pel nomcurt {} de {}",
											ui.ShortName, user);
									groupService.createGroup(ui.ShortName,
											ui.ShortName, ui.ShortName,
											"Anyone");
								} catch (Exception ee) {
									log.warn(
											"Error en la creació de llista de correu '"
													+ ui.ShortName
													+ "' (grup a google) per al nomcurt de "
													+ user, ee);
									throw new InternalErrorException2 ("UpdateUser "+user, ee, PAQUETE_GOOGLE);
								}
							}
						} catch (Exception e) {
							log.warn(
									"Error en la creació de llista de correu '"
											+ ui.ShortName
											+ "' (grup a google) per al nomcurt de "+user, e);
							throw new InternalErrorException2 ("UpdateUser "+user,e, PAQUETE_GOOGLE);
						}
						
						// El usuari és nou, no ha de pertanyer a aquesta llista
						// de correu (nomcurt)
						groupService.addMemberToGroup(ui.ShortName, user);
						*/
						
						// Atorguem el send-as del nomcurt@dominigoogle a
						// l'usuari actual 
						gmailSettingsService.createSendAs(user, ui.Name + " "
								+ llinatges, ui.ShortName + "@" + dominiUsuari,
								true);
						log.info("Creat enviar com a {} per a usuari {}",
								ui.ShortName + "@" + dominiUsuari, user);
					}
					
					log.info ("creat l'usuari {} amb èxit ",user,usuariEntry.getId());
				} else { // USUARI EXISTENT
					boolean actualitzaUsuariEntry = false;
					// Analitzem si estava inactiu.. per tornar a activar-lo
					if (usuariEntry.getLogin().getSuspended()) {
						log.info ("l'usuari {} estava marcat com a inactiu, el tornem a activar",user,null);
						usuariEntry.getLogin().setSuspended(false);
						actualitzaUsuariEntry = true;
						log.info("usuari '{}' marcat com a actiu", user, null);
					}
					if ( !ui.Name.equals(usuariEntry.getName().getGivenName()) || !llinatges.equals(usuariEntry.getName().getFamilyName()) ) { 
						usuariEntry.getName().setGivenName(ui.Name);
						usuariEntry.getName().setFamilyName(llinatges);
						actualitzaUsuariEntry = true;
					}
					if (actualitzaUsuariEntry) {//Només si hem fet canvis
						log.info("Actualitzant dades de l'usuari {}", user, null);
						updateUserGoogle(user, usuariEntry, dominiUsuari);
					}
					// Li atorguem nomcurt i li fem el send-as (ja s'ha
					// comprovat el ui.MailDomain)
					if (ui.ShortName != null) { // És únic a nivell de seu..
						
						// Cerquem els nomscurts d'aquest usuari
						ArrayList nicks = retrieveNicknames(user, dominiUsuari);
						if (nicks == null || (nicks!=null && nicks.size() ==0) ) {  
							// No existeix cap nick, s'ha de crear almenys el nomcurt
							if (!"".equals(ui.ShortName.trim())) { //shorname !=null
								// Verifiquem que no existisca cap llista (grup) a google
								NicknameEntry nick = retrieveNickname(ui.ShortName, dominiUsuari);
								if (nick!=null) { // ja existeix el àlies: verifiquem usuari propietari
									Login login = nick.getLogin();
									if (login!=null && !login.getUserName().equalsIgnoreCase(user)) {
										throw new InternalErrorException(
											"Ja existeix un altre usuari amb el mateix nomcurt "
													+ (login != null ? login.getUserName() : ""));
									} 
								} else {							
									// No existeix el nick, s'ha de crear
									// Comprovem abans que no existisca com a grup de google
									// (llista de correu).. perquè sinó dóna error al crear el nick
									try {							
										GenericEntry gs = groupService.retrieveGroup(ui.ShortName);
										// Si arribem aqui es que ja existeix
										if (gs != null)
											throw new InternalErrorException(
													"Error creant "
															+ ui.ShortName
															+ "@"
															+ dominiUsuari
															+ " ja existeix com a grup a google, s'ha d'esborrar el grup a google");
									} catch (AppsForYourDomainException e) {
										// NO EXISTEIX: correcte
										if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode()) ) {
											// Correcte
										} else {
											throw new InternalErrorException2(
													"Error creant " + ui.ShortName
															+ "@" + dominiUsuari, e);
										}
									}									
									// El creem
									nick = createNickname(user, ui.ShortName, dominiUsuari);
									Nickname n = nick.getNickname();
									Login login = nick.getLogin();
										log.info("Creat nickname {} per a l'usuari {}",
											n != null ? n.getName() : ui.ShortName,
											login != null ? login.getUserName() : user);
								}
							}
						} else {
							// Procesem els que té, per asegurar-nos que en té
							// almenys el nomcurt@dominiusuari
							boolean trobat = false;
							for (Iterator it = nicks.iterator(); !trobat && it.hasNext(); ) {
								String nick = (String) it.next();
								log.info ("Usuari {}: té el nick '{}'",user,nick);
								if (nick!=null && nick.equalsIgnoreCase(ui.ShortName)) //nomcurt
									trobat = true;
								else {
									// Hem d'esborrar el nick antic..
									deleteNickname(nick,dominiGoogle);
									log.info("Esborrem el nickname {} perquè l'usuari ja no el té", nick, null);
								}
							}
							if (!trobat) {
								NicknameEntry nick = createNickname(user, ui.ShortName, dominiUsuari);
								Nickname n = nick.getNickname();
								Login login = nick.getLogin();
								log.info("Creat nickname {} per a l'usuari {}",
										n != null ? n.getName() : ui.ShortName,
										login != null ? login.getUserName() : user);
								// Ara li posem el send-as nomcurt@domini (com a adreça per defecte)
								gmailSettingsService.createSendAs(user, ui.Name+" "+llinatges, ui.ShortName+"@"+dominiUsuari, true);
								log.info("Creat enviar com {} per a usuari {}",
										ui.ShortName + "@" + dominiUsuari, user);
								log.info ("Atorgat send-as {} per a usuari {}",ui.ShortName + "@" + dominiUsuari, user);
							}
						}						
						
						/*try {
							groupService.retrieveGroup(ui.ShortName); //nomcurt
						} catch (AppsForYourDomainException e) {
							// NO EXISTEIX: EL CREEM
							if (e.getErrorCode() == AppsForYourDomainErrorCode.EntityDoesNotExist) {
								// Hem de crear el grup a google (no existeix encara)
								try {
									log.info(
											"Creant llista de correu (grup a google) {} pel nomcurt de {}",
											ui.ShortName, user); //nomcurt
									groupService.createGroup(ui.ShortName,
											ui.ShortName, ui.ShortName,
											"Anyone");
								} catch (Exception ee) {
									log.warn(
											"Error en la creació de llista de correu '"
													+ ui.ShortName
													+ "' (grup a google) pel nomcurt de "
													+ user, ee);
									throw new InternalErrorException2(
											"UpdateUser "+user, ee, PAQUETE_GOOGLE);
								}
							}
						} catch (Exception e) {
							log.warn(
									"Error en la creació de llista de correu '"
											+ ui.ShortName
											+ "' (grup a google) pel nomcurt de "
											+ user, e);
							throw new InternalErrorException2(
									"UpdateUser "+user, e, PAQUETE_GOOGLE);
						}
						
						// Assignem l'usuari al grup (perque reba correus):
						if (!groupService.isMember(ui.ShortName, user)) { //nomcurt
							groupService.addMemberToGroup(ui.ShortName, user);
						}*/
						
						// Atorguem el send-as a l'usuari actual
						gmailSettingsService.createSendAs(user, ui.Name + " "
								+ llinatges, ui.ShortName + "@" + dominiUsuari,
								true);
						log.info("Establert enviar-com {} per a usuari {}",
								ui.ShortName + "@" + dominiUsuari, user);
					}
					
					log.info(
							"UpdateUser: usuari {}, actualitzades dades i establert enviar-com {}",
							user, ui.ShortName);
				}
				
				
				// Fem que siga membre del Organization Unit q li correspon (el seu grup primari)
				if (ui!=null && ui.PrimaryGroup!=null) {
					String grupPrimari = ui.PrimaryGroup;
					
					GroupInfo gi = null;
					
					try {
						gi = getServer().GetGroupInfo(grupPrimari);
					} catch (Throwable th) {
						log.warn("UpdateUser: Error obtening grup "+grupPrimari, th);
						throw new InternalErrorException2("UpdateUser "+user+": Error obtenint grup "+grupPrimari, th);
					}
					
					// Obtenim la ruta del grup primari de l'usuari
					// pot ésser buida o acabar en / si en té pares
					Map <String, Object> infoGrups = obteRutaPareGrup(gi);
					String rutaPareGrupPrimari = (String) infoGrups.get("ruta"); //pot ésser "" (sense pare)
					
					// Grup a google (trobat o crear)
					GenericEntry grupAGoogle = null;
					
					try {
						// Mirem si ja existeix aquesta ruta (ruta acaba en / o es "")
						grupAGoogle = retrieveOrganizationUnit(rutaPareGrupPrimari
								+ grupPrimari);
						// Actualitzem la seua descripció (si arribem aquí és perquè existeix)
						String descr = grupAGoogle.getProperty(OrgUnitProperty.DESCRIPTION);
						if (gi.Description!=null && !gi.Description.equals(descr)) {
							//Només si s'ha canviada la descripció
							Map<String, String> attributes = new HashMap<String, String>();
						      attributes.put(OrgUnitProperty.DESCRIPTION, gi.Description);
							
							// Actualitzem el grup (la seva descripció)
							updateOrganizationUnit(
									grupAGoogle.getProperty(OrgUnitProperty.PARENT_ORG_UNIT_PATH)
											+ "/" + grupPrimari, attributes);
						}
					} catch (AppsForYourDomainException e) {
						if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode())) {
							// Aquesta ruta no existeix, verifiquem si existeix
							// en altra ruta (!!)
							
							// Mirem si existeix ja com a OU en un altre puesto
							List<GenericEntry> totesOU = retrieveAllOrganizationUnits();
							boolean trobat = false;
							// per moure el grup a google (OU) si ja existeix:
							boolean mogut = false;							
							String rutaAntiga = null;
							Map<String, String> attributes = new HashMap<String, String>();
							
							
							if (totesOU != null) {
								for (Iterator<GenericEntry> it = totesOU.iterator(); !trobat && it.hasNext();) {
									GenericEntry grupG = it.next();
									Map<String, String> props = grupG.getAllProperties();
									String name = props.get(OrgUnitProperty.NAME);
									if (name != null && grupPrimari.equalsIgnoreCase(name)) {
										log.info("S'ha trobat el grup {} a la ruta de google {}",
												grupPrimari,
												props.get(OrgUnitProperty.PARENT_ORG_UNIT_PATH));
										log.info("Es mourà el grup {} a la ruta que li correspon {}",
												grupPrimari,
												rutaPareGrupPrimari);

										rutaAntiga = grupG.getProperty(OrgUnitProperty.PARENT_ORG_UNIT_PATH);
										// posem les noves
										// llevem la darrera barra de rutaPareGrup
										String rutaPareSenseBarra = rutaPareGrupPrimari;
										if (rutaPareSenseBarra.endsWith("/")) {
											rutaPareSenseBarra = rutaPareSenseBarra.substring(0, rutaPareSenseBarra.length()-1);
										}
										if ("".equals(rutaPareSenseBarra)) rutaPareSenseBarra="/"; 
										
										attributes.put(OrgUnitProperty.PARENT_ORG_UNIT_PATH, rutaPareSenseBarra);

										// actualizem el grup (si estava a
										// l'arrel la seua rutaAntiga = null)
										if (rutaAntiga == null)
											rutaAntiga = "";
										else if (!"".equals(rutaAntiga.trim()))
											rutaAntiga = rutaAntiga + "/";
									    
										try {
											updateOrganizationUnit(rutaAntiga + grupPrimari, attributes);
											log.info("Grup {} mogut a la ruta {}", grupPrimari, rutaPareGrupPrimari);
											trobat = true;
											mogut = true; //ja no s'ha de recolocar, ja s'ha fet
										} catch (AppsForYourDomainException ae) {
											// La ruta pare pot no existir
											if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(ae.getErrorCode())) {
												mogut = false; // per veure si s'ha de crear o moure
												trobat = true; // s'ha trobat encara q no a la seua ruta
											}
											else throw new InternalErrorException2 ("Error actualitzant la jerarquia del grup primari " +
													"de l'usuari, movent de '"+rutaAntiga+"' a '"+rutaPareGrupPrimari+"' ",ae);
										}
										grupAGoogle = grupG;
									}//if-grup_trobat
								}//for-grups
							}
							
							// si !trobat i !mogut ==> verifiquem pares i CREAR fill
							// si !trobat i mogut == no possible
							// si trobat i !mogut => existeix i s'ha de MOURE a la nova ruta (verificant pares)
							// si trobat i mogut  => no fem res (ja s'ha mogut)
							if (!trobat || (trobat && !mogut) ) {
								// Verifiquem que el grup pare existeix (anem per nivells)
								// Pot ésser que el grup no tinga pare.. 
								if (rutaPareGrupPrimari!=null && !"".equals(rutaPareGrupPrimari)) {
									String pares[] = rutaPareGrupPrimari.split("/");
									String rutaP = "";
									for (int i =0; i < pares.length; i++) {
										try {
											retrieveOrganizationUnit(rutaP+pares[i]);
										} catch (AppsForYourDomainException ge) {
											if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(ge.getErrorCode())) {
												String desc = pares[i];
												if (infoGrups.get(pares[i])!=null) {
													try {
														GroupInfo gri = (GroupInfo) infoGrups.get(pares[i]);
														desc = gri.Description;
													} catch (Throwable th) {}
												}
												createOrganizationUnit(pares[i], i != 0 ? rutaP : "/", desc, false);
											}
										}
										rutaP+=pares[i]+"/";
									}
								} 
								// No s'ha trobat el grup (OU): s'ha de crear (i ja existeixen els seus pares)
								// Fem xanxullo per a grups sense pare
								String ruta = rutaPareGrupPrimari != null
										&& "".equals(rutaPareGrupPrimari) ? "/"
										: rutaPareGrupPrimari;
								if (trobat && !mogut) {
									updateOrganizationUnit(rutaAntiga + grupPrimari, attributes);
									log.info("Grup {} mogut a la ruta {}", grupPrimari, rutaPareGrupPrimari);
								} else {
									grupAGoogle = createOrganizationUnit(gi.Name, ruta, gi.Description, false);
									log.info("Creat grup (OU) {} a la ruta pare {}", gi.Name, ruta);
								}
							}
							
						}//if_no_existeix
					}
					// Ara que hem verificat que el grup existeix i
					// està en la ruta correcta, obtenim la seua pertinença al OU
					try {
						GenericEntry userOU = retrieveOrganizationUser(user);
						
						if (userOU!=null) {
							String rutaActualOU = userOU.getProperty(OrgUnitProperty.ORG_UNIT_PATH);
							if (rutaActualOU!=null && !rutaActualOU.equals(rutaPareGrupPrimari+grupPrimari)) {
								//movem l'usuari a aquest OU
								updateOrganizationUser(user, rutaActualOU,
										rutaPareGrupPrimari + grupPrimari);
								log.info(
										"Movem l'usuari de la ruta de grup {} a la ruta de grup {}",
										rutaActualOU, rutaPareGrupPrimari
												+ grupPrimari);
							}
						}
					} catch (AppsForYourDomainException e) {
						// POT SER QUE ENCARA NO PERTANY A CAP OU
						if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode()) ) {
							//l'usuari està a l'arrel quan es crea
							updateOrganizationUser(user, "/",
									rutaPareGrupPrimari + grupPrimari);							
						}
					} catch (Exception e) {
						log.warn("Error atorgant l'usuari " + user
								+ " al grup(OU google) " + rutaPareGrupPrimari
								+ grupPrimari, e);
						throw new InternalErrorException2 ("UpdateUser "+user, e, PAQUETE_GOOGLE);
					}
					
 
					
				}
			} else {
				// USUARI NO ACTIU (S'HA DE DESACTIVAR, SI EXISTEIX)
				
				// Obtenim el (sub)domini de l'usuari
				// Si el ui que hem obtingut es nul, posem el domini de l'agent (per desactivar-lo, en cas que existisca) 
				//String domini = ui!=null ? ui.MailDomain : dominiGoogle;
				
				// Si és l'usuari administrador NO el desactivem
				if (!adminUser.equals(user)) { //distint de l'administrador
					// Mirem si ja existeix l'usuari a google
					UserEntry usuari;
					usuari = retrieveUser(user, dominiGoogle); // AL DOMINI DE GOOGLE (!!)
					
					// Si no existeix no hem de fer res...
					if (usuari != null) {
						// comprovem que no siga administrador a google
						if (usuari.getLogin() != null
								&& usuari.getLogin().getAdmin()) {
							log.info(
									"Usuari '{}' te rol d'administrador a google: no es desactivarà",
									user, null);
							return;
						}
						
						log.info("UpdateUser - Desactivant l'usuari al domini {}", user, dominiGoogle);
	
						// L'hem d'eliminar de totes les llistes de correu
						// (grups a google) als que pertany actualment
						// Obtenim el llistat de grupsGoogle als que pertany
						// l'usuari
						ArrayList<String> grupsPertanyUserGoogle = obteLlistesCorreuPertanyUsuari(user);
					    
					    // Eliminem l'usuari dels grups (un per un..)
					    for (Iterator it = grupsPertanyUserGoogle.iterator(); it.hasNext();) {
					    	String groupId = (String) it.next();
					    	groupService.deleteMemberFromGroup(groupId, user);
							log.info("Usuari {} esborrat del grup de google {}", user, groupId);
					    }
	
					    // I el desactivem (es comprova q no siga admin)
						suspendUser(user, dominiGoogle);
						log.info("UpdateUser - Usuari {} desactivat correctament", user, null);
						
					} 
	
				}
			}
			
		} catch (InternalErrorException e) {
			e.printStackTrace();
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException2(e.getMessage(), e, PAQUETE_GOOGLE);
		} 

	}
	

	public void UpdateUserPassword(String user, Password password,
			boolean mustchange) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub

	}

	public boolean ValidateUserPassword(String user, Password password)
			throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return false;
	}
	
	/**
	 * Obté les llistes de correu (grups a google) als que pertany l'usuari
	 * @param user
	 * @return
	 * @throws AppsForYourDomainException
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws ServiceException
	 */
	private ArrayList obteLlistesCorreuPertanyUsuari(String user)
			throws AppsForYourDomainException, MalformedURLException,
			IOException, ServiceException {
		
		ArrayList<String> grupsPertanyUserGoogle = new ArrayList();
		GenericFeed groupsFeed = null;
		Iterator<GenericEntry> groupsEntryIterator = null;
		groupsFeed = groupService.retrieveGroups(user, true); // només directes
		groupsEntryIterator = groupsFeed.getEntries().iterator();
		while (groupsEntryIterator.hasNext()) {
			// Mirem APPS_PROP_GROUP_NAME ?? en teoria son el mateix
			grupsPertanyUserGoogle.add(groupsEntryIterator.next().getProperty(
					AppsGroupsService.APPS_PROP_GROUP_ID));
		}

		return grupsPertanyUserGoogle;
	}
	

	/**
	   * Retrieves a user.
	   * 
	   * @param user The user you wish to retrieve.
	   * @return A UserEntry object of the retrieved user. 
	   * @throws AppsForYourDomainException If a Provisioning API specific occurs.
	   * @throws ServiceException If a generic GData framework error occurs.
	   * @throws IOException If an error occurs communicating with the GData
	   * service.
	   */
	private UserEntry retrieveUser(String user, String domini) throws  InternalErrorException {

		log.info("Retrieving user '{}'.", user, null);
		try {
			
			URL retrieveUrl = new URL(APPS_FEEDS_URL_BASE + domini + "/user/"
					+ SERVICE_VERSION + "/" + user);
			return userService.getEntry(retrieveUrl, UserEntry.class);
		} catch (AppsForYourDomainException e) {
			// Si l'usuari no existeix tornem null
			if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode()) ) {
				return null;
			}
			throw new InternalErrorException2("retrieveUser (" + user + ")", e,
					PAQUETE_GOOGLE);
		} catch (Exception e) {
			throw new InternalErrorException2("retrieveUser (" + user + ")", e,
					PAQUETE_GOOGLE);		
		}
	}
	
	 /**
	   * Creates a new user with an email account.
	   *
	   * @param username The username of the new user.
	   * @param givenName The given name for the new user.
	   * @param familyName the family name for the new user.
	   * @param password The password for the new user.
	   * @param passwordHashFunction Specifies the hash format of the password
	   * parameter
	   * @param quotaLimitInMb User's quota limit in megabytes.  This field is only
	   * used for domains with custom quota limits.
	   * @return A UserEntry object of the newly created user.
	   * @throws AppsForYourDomainException If a Provisioning API specific occurs.
	   * @throws ServiceException If a generic GData framework error occurs.
	   * @throws IOException If an error occurs communicating with the GData
	   * service.
	   */
	  private UserEntry createUser(String username, String givenName,
	      String familyName, String password, String passwordHashFunction,
	      Integer quotaLimitInMb, String domini)
	      throws AppsForYourDomainException, ServiceException, IOException {

	    log.info("Creating user '" + username + "'. Given Name: '" + givenName +
	        "' Family Name: '" + familyName +
	        (passwordHashFunction != null 
	            ? "' Hash Function: '" + passwordHashFunction : "") + 
	        (quotaLimitInMb != null 
	            ? "' Quota Limit: '" + quotaLimitInMb + "'." : "' for domain '") + 
	            " in domain '"+domini+"'"
	        ,null,null);

	    UserEntry entry = new UserEntry();
	    Login login = new Login();
	    login.setUserName(username);
	    login.setPassword(password);
	    if (passwordHashFunction != null) {
	      login.setHashFunctionName(passwordHashFunction);
	    }
	    entry.addExtension(login);

	    Name name = new Name();
	    name.setGivenName(givenName);
	    name.setFamilyName(familyName);
	    entry.addExtension(name);

	    if (quotaLimitInMb != null) {
	      Quota quota = new Quota();
	      quota.setLimit(quotaLimitInMb);
	      entry.addExtension(quota);
	    }

	    URL insertUrl = new URL( APPS_FEEDS_URL_BASE + domini + "/user/" + SERVICE_VERSION );
	    return userService.insert(insertUrl, entry);
	  }
	  
	  /**
	   * Suspends a user. Note that executing this method for a user who is already
	   * suspended has no effect.
	   * 
	   * @param user The user you wish to suspend.
	   * @throws AppsForYourDomainException If a Provisioning API specific occurs.
	   * @throws ServiceException If a generic GData framework error occurs.
	   * @throws IOException If an error occurs communicating with the GData
	   *         service.
	   */
	  private void suspendUser(String user, String domini)
	      throws AppsForYourDomainException, ServiceException, IOException {

	    URL retrieveUrl = new URL( APPS_FEEDS_URL_BASE + domini + "/user/" + SERVICE_VERSION + "/" + user);
	    UserEntry userEntry = userService.getEntry(retrieveUrl, UserEntry.class);
	    
	    if ( userEntry.getLogin() !=null && userEntry.getLogin().getAdmin()) {
			log.info(
					"Usuari '{}' és administrador, no es suspendrà el seu compte",
					user, null);
			return;
	    }
	    log.info("Deactivating user '{}'.",user,null);
	    userEntry.getLogin().setSuspended(true);

	    URL updateUrl = new URL(APPS_FEEDS_URL_BASE + domini + "/user/" + SERVICE_VERSION + "/" + user);
	    userService.update(updateUrl, userEntry);
	    log.info("User '{}' suspended.",user,null);
	  }
	  
	  /**
	   * Updates a user.
	   *
	   * @param user The user to update.
	   * @param userEntry The updated UserEntry for the user.
	   * @return A UserEntry object of the newly updated user. 
	   * @throws AppsForYourDomainException If a Provisioning API specific occurs.
	   * @throws ServiceException If a generic GData framework error occurs.
	   * @throws IOException If an error occurs communicating with the GData
	   * service.
	   */
	  private UserEntry updateUserGoogle(String user, UserEntry userEntry, String domini)
	      throws AppsForYourDomainException, ServiceException, IOException {

		log.info("Updating user '{}'.", user, null);

	    URL updateUrl = new URL(APPS_FEEDS_URL_BASE + domini + "/user/" + SERVICE_VERSION + "/" + user);
	    return userService.update(updateUrl, userEntry);
	  }


	public void UpdateUserAlias(String user) throws RemoteException,
			InternalErrorException {
		// En principi no fem res..
		return;
		
	}

	public void UpdateListAlias(String alias, String domain)
			throws RemoteException, InternalErrorException {
		
		if (alias == null)
			return;
		
		if (!this.dominiGoogle.equals(domain)) {
			// Hem de comprovar si existeix el àlies, pero s'ha canviat de domini?? NOO, abans es propaga l'anterior per esborrar-la
			return;
			
		} else {
			// Obtenim informació de la llista de correu:
			// array de {USU_CODI,null [nomcurt], mainDomain || LCO_NOM,DCO_CODI, mainDomain || ELC_ADRECA,null,mainDomain}
			String list[] = getServer().getMailListWithDomain(alias, domain);
			
			if (list == null) {
				// La lista ja no existeix a seycon, verifiquem 
				// q no existisca a google, i la borrem si existeix
				try {
					GenericEntry llistaBorrar = groupService.retrieveGroup(alias);
					if (llistaBorrar != null) {
						groupService.deleteGroup(alias); // L'esborrem ??
					}
					return; // Feina feta...
					
				} catch (AppsForYourDomainException e) {
					if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode())) {
						// NO EXISTEIX: SORTIM
						return;
					}
					throw new InternalErrorException2("UpdateListAlias "
							+ alias + "@" + domain, e, PAQUETE_GOOGLE);
				} catch (Exception e) {
					log.warn(
							"Error en la comprovació de si existeix a google la llista de correu '"
									+ alias + "@" + domain
									+ "' (grup a google)", e);
					throw new InternalErrorException2("UpdateListAlias "
							+ alias + "@" + domain, e, PAQUETE_GOOGLE);
				} 				
			}
			
			// Comprovar els seus usuaris (members)
			Set<String> membresSeycon = new HashSet<String>();  
			if (list != null) {
				membresSeycon.addAll(Arrays.asList(list));
			}
			
			// Ara tenim els membres de seycon: verifiquem els membres
			// de google
			// 1) Hem de verificar que la llista de correu
			// d'aquest domini, existisca (grup a google)
			try {
				groupService.retrieveGroup(alias);
			} catch (AppsForYourDomainException e) {
				// NO EXISTEIX: EL CREEM
				if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode()) ) {
					// Verifiquem que no exisisca com a nickname
					// (nomcurt@dominiGoogle)
					try {
						NicknameEntry nick = retrieveNickname(alias,
								dominiGoogle);
						if (nick == null) { // OK: no existeix com a nick
							// Hem de crear el grup a google
							log.info(
									"Creant llista de correu (grup a google) {}",
									alias, null);
							groupService.createGroup(alias, alias, alias,
									"Anyone");
						} else { // existeix el nickname
							// Analitzem el propietari: si és el mateix
							// que l'usuari de la llista: ok
							if (membresSeycon.size() > 1) {
								String errorMsg = "ERROR: Ja existeix el alias "
										+ alias
										+ " com a nickname a google de "
										+ "l'usuari "
										+ nick.getLogin().getUserName()
										+ " i aquesta llista a seycon en té més "
										+ "d'un membre " + membresSeycon.toString();
								log.info(errorMsg, null,null);
								Exception ex = new Exception (errorMsg);
								log.warn(errorMsg, ex);
								throw ex;
							} else if (membresSeycon.size()==1) {
								// Comprovem que el membre de la llista siga el
								// mateix que a  google
								String membreSeycon = membresSeycon.iterator().next();
								String propNickGoogle =nick.getLogin().getUserName()+"@"+dominiGoogle;
								if ( !propNickGoogle.equals(membreSeycon)) {
									String errorMsg = "S'ha trobat un nickname a google per a l'alias "
											+ alias
											+ " on el seu propietari "
											+ propNickGoogle
											+ " no es correspon amb el membre de la llista "
											+ membreSeycon
											+ " s'ha de verificar aquest nickname";
									Exception ex = new Exception (errorMsg);
									log.warn ( errorMsg, ex);
									throw ex;
								}
								// Ja no hem de fer res mes (és un nickname correcte)
								return; 
							} else if (membresSeycon.size() == 0) {
								log.info ("Esborrem nickname "+alias+"@"+dominiGoogle+ " perquè ja no el té cap usuari",null,null);
								deleteNickname(alias,dominiGoogle);
								return; 
							}
							
						}
					} catch (Exception ee) {
						log.warn("Error en la creació de llista de correu '"
								+ alias + "' (grup a google)", ee);
						throw new InternalErrorException2("UpdateListAlias "
								+ alias + "@" + domain, ee, PAQUETE_GOOGLE);
					}
				}
			} catch (Exception e) {
				log.warn("Error en la creació de llista de correu '" + alias
						+ "' (grup a google)", e);
				throw new InternalErrorException2("UpdateListAlias" + alias
						+ "@" + domain, e, PAQUETE_GOOGLE);
			} 
			
			// Ara obtenim els membres d'aquesta llista de correu
			GenericFeed membresLlista = null;
			try {
				membresLlista = groupService.retrieveAllMembers(alias);
			} catch (Exception e) {
				log.warn(
						"Error en la obtenció dels membres de llista de correu  de google '"
								+ alias + "@" + domain + "' (grup a google)", e);
				throw new InternalErrorException2("UpdateListAlias " + alias
						+ "@" + domain, e, PAQUETE_GOOGLE);
			}
			
			Set<String> membresGoogle = new HashSet<String>();
			
			if (membresLlista != null) {
			
				List<GenericEntry> membres = membresLlista.getEntries();
				for (Iterator<GenericEntry> it = membres.iterator(); it.hasNext(); ) {
					GenericEntry membre = it.next();
					membresGoogle.add(membre.getProperty(OrgGroupMember.MEMBER_ID));
					//log.info (membre.getAllProperties().toString(),null,null);
				}
			}
				
			// Comparació de llistes
			for (Iterator<String> it = membresSeycon.iterator(); it.hasNext(); ) {
				String membre = it.next();
				if (membresGoogle.contains(membre)) {
					membresGoogle.remove(membre);
					it.remove();
				}
			}
			
			// Ara: membresSeycon = ADD i membresGoogle = REMOVE
			// REMOVE
			for (Iterator<String> it = membresGoogle.iterator(); it.hasNext();) {
				String membre = it.next();
				try {
					groupService.deleteMemberFromGroup(alias, membre);
				} catch (Throwable th) {
					throw new InternalErrorException2("Error esborrant "
							+ membre + " de la llista de correu[grup google] "
							+ alias, th, PAQUETE_GOOGLE);
				}
				log.info("Esborrat {} de la llista de correu[grup google] {}",
						membre, alias);
			}
			
			// ADD
			for (Iterator<String> it = membresSeycon.iterator(); it.hasNext();) {
				String membre = it.next();
				try {
					groupService.addMemberToGroup(alias, membre);
				} catch (Throwable th) {
					throw new InternalErrorException2("Error afegint " + membre
							+ " a la llista de correu[grup google] " + alias,
							th, PAQUETE_GOOGLE);
				}
				log.info("Afegim {} a la llista de correu[grup google] {}",
						membre, alias);
			}

		}
		

		
	}
	  
	
	
	/**
	 * Generar una dirección de correo a partir de alias y dominio
	 * 
	 * @param alias
	 *            Nombre a figurar a la izquierda de la arroba
	 * @param domain
	 *            Subdominio opcional a figurar a la derecha de la arroba
	 * @return dirección válida de correo
	 */
	private String textify(String alias, String domain) {
		if (domain == null && alias.indexOf("@") >= 0)
			return alias;
		else if (domain == null)
			return alias + "@caib.es";
		else {
			// Fem un cas especial si el domain conté .
			if (domain.indexOf(".") == -1)
				return alias + "@" + domain + ".caib.es";
			else
				// cas de domini principal distint a caib.es
				return alias + "@" + domain;
		}
	}
	
	 /**
	   * Creates an alias email for the user identified by the given email address.
	   * 
	   * @param aliasEmail The alias email to create for the given user.
	   * @param userEmail User's primary email address.
	   * @return the newly created alias GenericEntry instance.
	   * @throws AppsForYourDomainException If a Provisioning API specific error
	   *         occurs.
	   * @throws ServiceException If a generic GData framework error occurs.
	   * @throws IOException If an error occurs communicating with the GData
	   *         service.
	   */
	  private GenericEntry createAlias(String aliasEmail, String userEmail)
	      throws AppsForYourDomainException, MalformedURLException, IOException, ServiceException {
	    GenericEntry entry = new GenericEntry();
	    entry.addProperty("userEmail", userEmail);
	    entry.addProperty("aliasEmail", aliasEmail);
	    return appsPropertyService.insert(new URL("https://apps-apis.google.com/a/feeds/alias/2.0/" + dominiGoogle),
	        entry);
	  }

	  /**
	   * Retrieves the alias entry for the given email alias.
	   * 
	   * @param aliasEmail the user email alias.
	   * @return GenericEntry
	   * @throws AppsForYourDomainException If a Provisioning API specific error
	   *         occurs.
	   * @throws ServiceException If a generic GData framework error occurs.
	   * @throws IOException If an error occurs communicating with the GData
	   *         service.
	   */
	  private GenericEntry retrieveAlias(String aliasEmail) throws AppsForYourDomainException,
	      MalformedURLException, IOException, ServiceException {

	    return appsPropertyService.getEntry(new URL("https://apps-apis.google.com/a/feeds/alias/2.0/" + dominiGoogle
	        + "/" + aliasEmail), GenericEntry.class);
	  }
	

	
	/*
	 * PART DE LES Organization Units
	 */
	  
	/**
	 * Retrieves the customer Id that will be used for all other operations.
	 * S'empra des del mètod init
	 * 
	 * @param domain
	 * @return String
	 * @throws AppsForYourDomainException
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws ServiceException
	 */
	  private String retrieveCustomerId(String domain)
			throws AppsForYourDomainException, MalformedURLException,
			IOException, ServiceException {
		GenericEntry entry = appsPropertyService
				.getEntry(
						new URL(
								"https://apps-apis.google.com/a/feeds/customer/2.0/customerId"),
						GenericEntry.class);
		if (entry != null)
			return entry.getProperty("customerId");
		else
			return null;
	}	
	
	/**
	 * Retrieves an organization unit from the customer's domain.
	 * 
	 * @param orgUnitPath
	 *            the path of the unit to be retrieved for e.g /corp
	 * @return a GenericEntry instance.
	 * @throws AppsForYourDomainException
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws ServiceException
	 */
	private GenericEntry retrieveOrganizationUnit(String orgUnitPath) throws AppsForYourDomainException, MalformedURLException,
			IOException, ServiceException {
		// Codifiquem el grup.. per eviar posibles problemes de codificació
		orgUnitPath = URLEncoder.encode(orgUnitPath, "UTF-8");
		if (orgUnitPath!=null) orgUnitPath = orgUnitPath.replaceAll("%2F", "/");
		GenericEntry entry = appsPropertyService.getEntry(new URL("https://apps-apis.google.com/a/feeds/orgunit/2.0/" + customerId
				+ "/" + orgUnitPath), GenericEntry.class);
		return entry;

	}
	
	/**
	 * Create a new organization unit under the given parent.
	 * 
	 * @param orgUnitName
	 *            the new organization name.
	 * @param parentOrgUnitPath
	 *            the path of the parent organization unit where '/' denotes the
	 *            root of the organization hierarchy. For any OrgUnits to be
	 *            created directly under root, specify '/' as parent path.
	 * @param description
	 *            a description for the organization unit created.
	 * @param blockInheritance
	 *            if true, blocks inheritance of policies from parent units.
	 * @return a GenericEntry instance of the newly created org unit.
	 * @throws AppsForYourDomainException
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws ServiceException
	 */
	private GenericEntry createOrganizationUnit(String orgUnitName,
			String parentOrgUnitPath, String description,
			boolean blockInheritance) throws AppsForYourDomainException,
			MalformedURLException, IOException, ServiceException {
		GenericEntry entry = new GenericEntry();
		entry.addProperty("parentOrgUnitPath", parentOrgUnitPath);
		entry.addProperty("description", description);
		entry.addProperty("name", orgUnitName);
		entry.addProperty("blockInheritance", String.valueOf(blockInheritance));
		entry = appsPropertyService.insert(new URL(
				"https://apps-apis.google.com/a/feeds/orgunit/2.0/"
						+ customerId), entry);
		return entry;
	}

	
	/**
	 * Retrieves all organization units for the given customer account.
	 * 
	 * @param customerId
	 * @return a List of organization unit entries
	 * @throws AppsForYourDomainException
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws ServiceException
	 */
	private List<GenericEntry> retrieveAllOrganizationUnits()
			throws AppsForYourDomainException, MalformedURLException,
			IOException, ServiceException {
		return retrieveAllPages(new URL(
				"https://apps-apis.google.com/a/feeds/orgunit/2.0/"
						+ customerId + "?get=all"));

	}
	
	/**
	 * Utility method that follows the next link and retrieves all pages of a
	 * feed.
	 * 
	 * @param feedUrl
	 *            Url of the feed.
	 * @return a List of GenericEntries in the feed queried.
	 * @throws ServiceException
	 *             If a generic GData framework error occurs.
	 * @throws IOException
	 *             If an error occurs communicating with the GData service.
	 */
	private List<GenericEntry> retrieveAllPages(URL feedUrl)
			throws IOException, ServiceException {
		List<GenericEntry> allEntries = new ArrayList<GenericEntry>();
		try {
			do {
				GenericFeed feed = appsPropertyService.getFeed(feedUrl,
						GenericFeed.class);
				allEntries.addAll(feed.getEntries());
				feedUrl = (feed.getNextLink() == null) ? null : new URL(feed
						.getNextLink().getHref());
			} while (feedUrl != null);
		} catch (ServiceException se) {
			AppsForYourDomainException ae = AppsForYourDomainException
					.narrow(se);
			throw (ae != null) ? ae : se;
		}
		return allEntries;
	}
	
	
	/**
	 * Actualitza l'unitat organitzativa (grup de seycon) a google
	 * @param orgUnitPath
	 * @param entry
	 * @return
	 * @throws AppsForYourDomainException
	 * @throws MalformedURLException
	 * @throws IOException
	 * @throws ServiceException
	 */
	/*private GenericEntry updateOrganizationUnit(String orgUnitPath,
			GenericEntry entry)
			throws AppsForYourDomainException, MalformedURLException,
			IOException, ServiceException {
		return appsPropertyService.update(new URL(
				"https://apps-apis.google.com/a/feeds/orgunit/2.0/"
						+ customerId + "/" + orgUnitPath), entry);
	}*/
	
	
	public GenericEntry updateOrganizationUnit(String orgUnitPath,
			Map<String, String> attributes) throws AppsForYourDomainException,
			MalformedURLException, IOException, ServiceException {
		GenericEntry entry = new GenericEntry();
		for (Map.Entry<String, String> mapEntry : attributes.entrySet()) {
			String value = mapEntry.getValue();
			if (value == null) {// || value.length() == 0) {
				continue;
			}
			String key = mapEntry.getKey().toString();

			if (key.equals(OrgUnitProperty.NAME)) {
				entry.addProperty(OrgUnitProperty.NAME, value);
			} else if (key.equals(OrgUnitProperty.PARENT_ORG_UNIT_PATH)) {
				entry.addProperty(OrgUnitProperty.PARENT_ORG_UNIT_PATH, value);
			} else if (key.equals(OrgUnitProperty.DESCRIPTION)) {
				entry.addProperty(OrgUnitProperty.DESCRIPTION, value);
			} else if (key.equals(OrgUnitProperty.BLOCK_INHERTANCE)) {
				entry.addProperty(OrgUnitProperty.BLOCK_INHERTANCE, value);
			} else if (key.equals(OrgUnitProperty.USERS_TO_MOVE)) {
				entry.addProperty(OrgUnitProperty.USERS_TO_MOVE, value);
			}
		}
		return appsPropertyService.update(new URL(
				"https://apps-apis.google.com/a/feeds/orgunit/2.0/"
						+ customerId + "/" + orgUnitPath), entry);
	}

	/**
	   * Updates the organization of the given user in a given organization.
	   * 
	   * @param orgUserEmail the email address of the user
	   * @param oldOrgUnitPath optional: the old organization unit path. If
	   *        specified, validates the OrgUser's current path.
	   * @param newOrgUnitPath the new organization unit path.
	   * @return a GenericEntry with the updated organization user.
	   * @throws AppsForYourDomainException
	   * @throws MalformedURLException
	   * @throws IOException
	   * @throws ServiceException
	   */
	  private GenericEntry updateOrganizationUser(String user,
	      String oldOrgUnitPath, String newOrgUnitPath) throws AppsForYourDomainException,
	      MalformedURLException, IOException, ServiceException {
	    GenericEntry entry = new GenericEntry();
		String orgUserEmail = user + "@" + dominiGoogle;
	    if (oldOrgUnitPath != null && oldOrgUnitPath.length() != 0) {
	      entry.addProperty("oldOrgUnitPath", oldOrgUnitPath);
	    }
	    entry.addProperty("orgUnitPath", newOrgUnitPath);
	    return appsPropertyService.update(new URL("https://apps-apis.google.com/a/feeds/orguser/2.0/" + customerId
	        + "/" + orgUserEmail), entry);
	  }
	  
	  
	  /**
	   * Retrieves the details of a given organization user.
	   * 
	   * @param customerId
	   * @param orgUserEmail the email address of the organization user.
	   * @return a GenericEntry instance
	   * @throws AppsForYourDomainException
	   * @throws MalformedURLException
	   * @throws IOException
	   * @throws ServiceException
	   */
	private GenericEntry retrieveOrganizationUser(String user)
			throws AppsForYourDomainException, MalformedURLException,
			IOException, ServiceException {
		String orgUserEmail = user + "@" + dominiGoogle;
		return appsPropertyService.getEntry(new URL(
				"https://apps-apis.google.com/a/feeds/orguser/2.0/"
						+ customerId + "/" + orgUserEmail), GenericEntry.class);

	}
	

	/*
	 * PART DELS NICKNAMES
	 */

	/**
	 * Retrieves a nickname.
	 * 
	 * @param nickname
	 *            The nickname you wish to retrieve.
	 * @return A NicknameEntry object of the newly created nickname.
	 * @throws AppsForYourDomainException
	 *             If a Provisioning API specific occurs.
	 * @throws ServiceException
	 *             If a generic GData framework error occurs.
	 * @throws IOException
	 *             If an error occurs communicating with the GData service.
	 */
	public NicknameEntry retrieveNickname(String nickname, String domini)
			throws InternalErrorException {
		log.info("Checking if nickname {} exists", nickname, null);

		NicknameEntry nick = null;
		try {
			URL retrieveUrl = new URL(APPS_FEEDS_URL_BASE + domini
					+ "/nickname/" + SERVICE_VERSION + "/" + nickname);

			nick = nicknameService.getEntry(retrieveUrl, NicknameEntry.class);
		} catch (AppsForYourDomainException e) {
			if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(e.getErrorCode()) ) {
				log.info("Nickname {} does not exists", nickname, null);
				return null;
			}
		} catch (Exception e) {
			throw new InternalErrorException2(
					"Error recuperant nick de l'usuari " + nickname, e);
		}
		return nick;
	}

	/**
	 * Retrieves all nicknames for the given username.
	 * 
	 * @param user
	 *            The user for which you want all nicknames.
	 * @return A NicknameFeed object with all the nicknames for the user.
	 * @throws AppsForYourDomainException
	 *             If a Provisioning API specific occurs.
	 * @throws ServiceException
	 *             If a generic GData framework error occurs.
	 * @throws IOException
	 *             If an error occurs communicating with the GData service.
	 */
	private ArrayList retrieveNicknames(String user, String domini)
			throws AppsForYourDomainException, ServiceException, IOException {
		log.info("Retrieving nicknames for user '{}'.", user, null);
		ArrayList<String> nickNames = new ArrayList();

		URL feedUrl = new URL(APPS_FEEDS_URL_BASE + domini + "/nickname/"
				+ SERVICE_VERSION);
		AppsForYourDomainQuery query = new AppsForYourDomainQuery(feedUrl);
		query.setUsername(user);
		NicknameFeed nicks = nicknameService.query(query, NicknameFeed.class);

		for (Iterator<NicknameEntry> it = nicks.getEntries().iterator(); it
				.hasNext();) {
			NicknameEntry n = (NicknameEntry) it.next();
			Nickname nick = n.getNickname();
			nickNames.add(nick.getName());
		}

		return nickNames;
	}

	/**
	 * Creates a nickname for the username.
	 * 
	 * @param username
	 *            The user for which we want to create a nickname.
	 * @param nickname
	 *            The nickname you wish to create.
	 * @return A NicknameEntry object of the newly created nickname.
	 * @throws AppsForYourDomainException
	 *             If a Provisioning API specific occurs.
	 * @throws ServiceException
	 *             If a generic GData framework error occurs.
	 * @throws IOException
	 *             If an error occurs communicating with the GData service.
	 */
	private NicknameEntry createNickname(String username, String nickname,
			String domini) throws AppsForYourDomainException, ServiceException,
			IOException {

		log.info("Creating nickname '{}' for user '{}'.", nickname, username);

		NicknameEntry entry = new NicknameEntry();
		Nickname nicknameExtension = new Nickname();
		nicknameExtension.setName(nickname);
		entry.addExtension(nicknameExtension);

		Login login = new Login();
		login.setUserName(username);
		entry.addExtension(login);

		URL insertUrl = new URL(APPS_FEEDS_URL_BASE + domini + "/nickname/"
				+ SERVICE_VERSION);
		return nicknameService.insert(insertUrl, entry);
	}
	
	 /**
	   * Deletes a nickname.
	   *
	   * @param nickname The nickname you wish to delete.
	   * @throws AppsForYourDomainException If a Provisioning API specific occurs.
	   * @throws ServiceException If a generic GData framework error occurs.
	   * @throws IOException If an error occurs communicating with the GData
	   * service.
	   */
	  private void deleteNickname(String nickname, String domini)
	      throws AppsForYourDomainException, ServiceException, IOException {

	    log.info("Deleting nickname '" + nickname + "'.",null,null);

	    URL deleteUrl = new URL(APPS_FEEDS_URL_BASE + domini + "/nickname/" + SERVICE_VERSION + "/" + nickname);
	    nicknameService.delete(deleteUrl);
	  }



	/* 
	 * Gestiona les bústies compartides (són rols de l'agent)
	 * (non-Javadoc)
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String, java.lang.String)
	 */
	public void UpdateRole(String role, String bd) throws RemoteException, InternalErrorException {

		if (bd == null || !getName().equals(bd))
			return;
		
		UserInfo[] usuarisBustia = null;

		// Mirem si el rol (bústia compartida) encara existeix al seycon
		try {
			RoleInfo ri = getServer().GetRoleInfo(role, bd);
			usuarisBustia = getServer().GetRoleUsersActiusInfo(role, bd);

			// Mirem si existeix la bústia com a usuari a google
			log.info("Cerquem la bústia compartida (role) {}@{} ", role, bd);
			UserEntry usuariEntry = retrieveUser(role, dominiGoogle);
			if (usuariEntry == null) { // La bústia encara no existeix: la creem
				log.info("la bústia compartida {} no existeix a google, la creem", role, null);
				// Donem d'alta a l'usuari en google
				String password = generateRandomUserPassword(); 
				// Nom = "bústia compartida",  llinatges= la descripció del rol
				usuariEntry = createUser(ri.name, "bústia compartida", ri.description, password, null, null, dominiGoogle);
				
				// L'atorguem com al seu OU la carpeta bústie compartides
				try {
					retrieveOrganizationUnit(GRUP_BUSTIES_COMPARTIDES);
				} catch (AppsForYourDomainException ae) {
					if (AppsForYourDomainErrorCode.EntityDoesNotExist.equals(ae.getErrorCode()) ) {
						// Aquesta ruta no existeix, verifiquem si existeix
						log.info("Creant grup a google (OU) per a les bústies compartides " + GRUP_BUSTIES_COMPARTIDES, null, null);
						createOrganizationUnit(GRUP_BUSTIES_COMPARTIDES, "/", DESCRIPCIO_GRUP_BUSTIES_COMPARTIDES, false);
					}
				}
				
				// Afegim l'usuari creat a aquest OU per a bústies compartides
				updateOrganizationUser(role, "/", GRUP_BUSTIES_COMPARTIDES);
			} else {
				boolean actualitzaUsuariEntry = false;
				// Mirem si l'usuari és suspés
				if (usuariEntry.getLogin().getSuspended()) {
					log.info ("l'usuari {} de la bústia compartida estava marcat com a inactiu, el tornem a activar",role,null);
					usuariEntry.getLogin().setSuspended(false);
					actualitzaUsuariEntry = true;
					log.info("usuari '{}' marcat com a actiu", role, null);
				}

				
				// Actualitzem els seus llinatges (si ha canviat) - és la descripció del rol
				if ( /*!ri.description.equals(usuariEntry.getName().getGivenName()) ||*/ !ri.description.equals(usuariEntry.getName().getFamilyName()) ) { 
					//usuariEntry.getName().setGivenName(ri.description);
					usuariEntry.getName().setFamilyName(ri.description);
					actualitzaUsuariEntry = true;
				}
				
				if (actualitzaUsuariEntry) {
					updateUserGoogle(ri.name, usuariEntry, dominiGoogle);
					log.info("Actualitzant nom de l'usuari de la bústia compartida {} amb nom = {}", ri.name, ri.description);
				}
				
			}
			
			// Guardem els usuaris de seycon
			Set membresSeycon = new HashSet<String>();
			if (usuarisBustia != null) {
				for (int i=0; i < usuarisBustia.length; i++) {
					if (usuarisBustia[i].ShortName!=null) { //pot no tindre nomcurt
						String correuUsuari = textify(usuarisBustia[i].ShortName, usuarisBustia[i].MailDomain);
						membresSeycon.add(correuUsuari);
					}
				}
			}
			
			// La bústia ja existiex a google, mirem els seus usuaris actuals
			Set<String> membresGoogle = new HashSet();
			if (usuariEntry.getLogin() != null) {
				List<Map<String, String>> usersBustia = gmailSettingsService.retrieveEmailDelegates(usuariEntry.getLogin()
						.getUserName());
				if (usersBustia != null) {
					for (Iterator<Map<String, String>> it = usersBustia.iterator(); it.hasNext();) {
						Map<String, String> m = it.next();
						// afegim adreça de correu
						membresGoogle.add(m.get(Constants.ADDRESS)); 
					}
				}
			}	
			
			// Comparació de llistes
			for (Iterator<String> it = membresSeycon.iterator(); it.hasNext();) {
				String membre = it.next();
				if (membresGoogle.contains(membre)) {
					membresGoogle.remove(membre);
					it.remove();
				}
			}

			// Ara: membresSeycon = ADD i membresGoogle = REMOVE
			// REMOVE
			for (Iterator<String> it = membresGoogle.iterator(); it.hasNext();) {
				String membre = it.next();
				try {
					// Esborrem de la bústia l'adreça de l'usuari que ja no pertany
					gmailSettingsService.deleteEmailDelegate(role, membre);
				} catch (Throwable th) {
					throw new InternalErrorException2("Error esborrant " + membre + " de la bústia compartida [usuari a google] " + role, th,
							PAQUETE_GOOGLE);
				}
				log.info("Esborrat {} de la bústia compartida [usuari a google] {}", membre, role);
			}

			// ADD
			for (Iterator<String> it = membresSeycon.iterator(); it.hasNext();) {
				String correuUsuari = it.next();
				try {
					// Afegim l'adreça de correu 
					gmailSettingsService.addEmailDelegate(role, correuUsuari);
				} catch (AppsForYourDomainException e) {
					if (AppsForYourDomainErrorCode.EntityNameNotValid.equals(e.getErrorCode())) {
						String msgError = "UpdateRole " + role + ". Error: Només es poden afegir adreces de domini de l'agent de "
								+ "google a les bústies compartides. No es pot afegir: " + correuUsuari;
						log.warn(msgError, e, null);
						throw new InternalErrorException2(msgError, e, PAQUETE_GOOGLE);
					}
					log.warn("S'ha produit un error ", e);
					throw new InternalErrorException2("Error",e,PAQUETE_GOOGLE);
				} catch (Throwable th) {
					throw new InternalErrorException2("Error afegint correu " + correuUsuari
							+ " a la bústia compartida [usuari a google] " + role, th, PAQUETE_GOOGLE);
				}
				log.info("Afegim {} a la bústia compartida [usuari a google] {}", correuUsuari, role);
			}

			
		} catch (UnknownRoleException e) {
			// Hem d'esborrar l'usuari (if exists)
			
			UserEntry usuariEntry = retrieveUser(role, dominiGoogle);
			if (usuariEntry != null) { // La si existeix: marquem el compte de
										// correu com a suspes
				// No s'esborra... es suspén el compte (no esborrar correus)
				try {
					suspendUser(role, dominiGoogle);
					log.info("El rol {} ja no existeix, marquem el compte de la bústia com a suspés", role, null);
				} catch (Exception ee) {
					log.warn("Error en la suspensió del compte de bústia compartida (rol) '" + role + "' (usuari a google)", ee);
					throw new InternalErrorException2("UpdateRole" + role + "@" + bd, ee, PAQUETE_GOOGLE);
				}
			}
		} catch (InternalErrorException ie) {
			throw ie;
		} catch (Exception e) {
			log.warn("Error en l'actualització de bústia compartida (rol) '" + role
					+ "' (usuari a google)", e);
			throw new InternalErrorException2("UpdateRole" + role
					+ "@" + bd, e, PAQUETE_GOOGLE);
		} 
				
		

	}

}
