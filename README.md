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

## Running

Available as Docker container (Linux Alpine of Windows 1809 nanoserver)

```
docker run -d `
  --restart=always `
  --name registry-auth `
  -v C:\docker\registry-auth-config:/app/config:ro `
  -p 5001:5001 `
  docker-registry.local:5000/dockertokenauthentication:latest
```

- Map the docker token authentication configuration to /app/config

Run the registry using the token authentication server

```
docker run -d `
  --restart=always `
  --name registry `
  -v D:\docker\local-cert:/certs `
  -v D:\docker\registry-data:/var/lib/registry `
  -e REGISTRY_HTTP_ADDR=0.0.0.0:443 `
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/docker-registry-tls.pem `
  -e REGISTRY_HTTP_TLS_KEY=/certs/docker-registry-tls.key `
  -e REGISTRY_HTTP_SECRET="my-secret" `
  -e REGISTRY_AUTH=token `
  -e REGISTRY_AUTH_TOKEN_REALM=https://docker-registry.local:5001/auth `
  -e REGISTRY_AUTH_TOKEN_SERVICE="Docker registry" `
  -e REGISTRY_AUTH_TOKEN_ISSUER="docker-auth.local" `
  -e REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE="/certs/docker-auth.pem" `
  -e REGISTRY_STORAGE_DELETE_ENABLED=true `
  -p 5000:443 `
  registry:2
```
