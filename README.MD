Start the keycloak docker service using 
`Docker compose up -d`

Keycloak starts in port 8088

### Create new realm for the app
Goto Keycloak console using http://localhost:8088 and create a new Realm called 'food-ordering-realm'


### Create new Client
Next Create a new client under the above realm called 'food-ordering-client' of type 'OpenID Connect'.
Other Configurations for the client:

Set type to 'OpenID Connect'
Turn on client authentication and turn off Authorization
Set root url to: http://localhost:8082/
Set Access Type to confidential
Add Valid Redirect URIs (each URI on a new line):
http://localhost:8082/
http://localhost:8082/menu
http://localhost:8082/login/oauth2/code/keycloak
Set Web Origins: http://localhost:8082

Goto the Credentials tab
Copy the Secret field's value for use in the application configuration

### Create new user(s)
Go to Users and click "Add user"
Set a username (e.g., testuser)
In Credentials tab:
Set a password
    Disable "Temporary"



