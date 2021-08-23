# DockerTokenAuthentication
Conditional access for a Docker Container Registry

## Implements Docker Token Authentication Specification  
https://docs.docker.com/registry/spec/auth/token/  
https://docs.docker.com/registry/spec/auth/oauth/  

## Configuration

### Server (and TLS)

```
"serverBindings": [
	{
		"port": 5001,
		"config": {
			"serverCertificateProvider": "WindowsStore",
			"serverCertificate": "CN=Docker registry TLS"
		}
	}
],
```

__port__: port number to listen on  
__config__: the certificate to use for TLS (specify null for plain HTTP)  
__serverCertificateProvider__: Blob/File/WindowsStore  
__serverCertificate__: depending on serverCertificateProvider, **blob**: base64 value of the pfx, **file**: path to the pfx, **WindowsStore**: subject of the certificate  
__serverCertificatePasswordProvider__: None/Plain (optional)  
__serverCertificatePassword__: depending on serverCertificateProvider, **plain**: plain text password  

### Docker registry access

```
"tokenAuthentication": {
	"issuer": "docker-auth.local",
	"eccKey": "MIGHAg...",
	"accounts": [
		{
			"registry": "Docker registry",
			"username": "foo",
			"password": "bar",
			"registryAccess": {
				"scopedAccess": {
					"catalog": [ "*" ]
				}
			},
			"repositoryAccess": {
				"access": [ "push", "pull", "delete" ]
			}
		}
	]
}

```

__issuer__: issuer  
__eccKey__: PKCS8 ECC Private Key  
__accounts__: accounts allowed to access the registry  
__registryAccess__ / __repositoryAccess__: access to the registry or repository  
__access__: access to all repositories  
__scopedAccess__: per repository accesss  

Grant only pull access to 'samalba/my-app'    
```
"repositoryAccess": {
	"scopedAccess": {
		"samalba/my-app": [ "pull" ]
	}
}
```
