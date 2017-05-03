 # ut-identity
The identity module defines an authentication API in ut5. The API deals with identifying the user that is associated with specific request or message. The module aims to support various methods of identifying the user, such as username/password, session, fingerprint, etc. The module provides a default functionality and allows overriding the default functionality in each implementation. API is defined in the "identity" namespace and consists of the following methods:

## identity.check(auth)
This method validates the user identity and optionally creates a session. 

### Parameters:

**auth** - an object, containing properties that allow the following functionality:

- **auth.username**, **auth.password** - when these are provided, the identity is determined based on username and password.
- **auth.newPassword** - when password has expired
- **auth.fingerPrint**  - when this is provided, the identity is determined based on biometric scan of the user's finger.
- **auth.userId** - when this is provided together with auth.fingerPrint, then the fingerprint is only matched against the specified user.
- **auth.sessionId** - when this is provided, the identity is determined by the existence of an active session with the specified id.
- **auth.twoFA** - two factor authentication specific data can be passed in this property.
- **auth.channel** - used to limit session count per channel.
- **auth.sso** - single sign on specific data can be passed in this property.
- **auth.sessionData** - an optional object, which determines if a session should be created during the authentication and what data to be persisted in the session. This object can contain arbitrary properties, but the following are recognized by the standard built in functionality:
    - **auth.sessionData.language** - sets the language for the session.

### Result:
The method returns a promise object that can have the following properties:

For successful authentication:

- **userId** - id of the identified user.
- **sessionId** - id of the created session (optional).
- **groups** - list of groups that this user belongs to (optional). 
- **roles** - list of roles assigned to this user (optional).
- **rights** - map of the effective rights assigned to this user (optional).

If any of the groups, roles and rights properties is returned, it is mandatory that identity.reloadSession method is implemented and invoked at appropriate places, where groups, roles and rights of the user may change.

For unsuccessful authentication:

- **errorCode** - unique code (string), that identifies the error.
- **errorMessage** - debug message that can be logged to the audit log.
- **errorPrint** - user friendly error message.

## identity.closeSession(criteria)
This method closes user's session.

### Parameters:
**criteria** - an object, containing properties that allow the following functionality:

- **criteria.sessionId** - determines the id of the session to be closed.
- **criteria.userId** - causes all sessions of the specified user to be closed.
- **criteria.channel** - used to limit closing of session per channel when closing more sessions (optional)

### Result:
For success returns an array containing the identifiers of the closed sessions. For error returns an error object similar to the identity.check method.

## identity.reloadSession(criteria)
This method reloads cached session data for users.

### Parameters:
**criteria** - an object, containing properties that define sessions for which users to be reloaded. The following properties are supported by default:

- **criteria.userId** - array used to limit reloading to the specified user ids.
- **criteria.group** - array used to limit reloading to the specified user groups.
- **criteria.role** - array used to limit reloading to the specified user roles.

### Result:
For success returns an array containing the identifiers of the reloaded sessions. For error returns an error object similar to the identity.check method.

## identity.changePassword(auth)
This method changes user's password.

### Parameters:
**auth** - an object, containing properties that allow the following functionality:

- **auth.userId** - determines the for which user to change the password
- **auth.password** - specifies the new password
- **auth.expire** - boolean property, making the password to expire immediately. Depending on policies, an empty password may be allowed when auth.expire is true.
