# & docker build -f ".\DockerTokenAuthentication\Dockerfile" --force-rm -t DockerTokenAuthentication "."
# & docker build -f ".\DockerTokenAuthentication\Dockerfile.Windows" --force-rm -t DockerTokenAuthentication "."
& 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe' .\DockerTokenAuthentication\DockerTokenAuthentication.csproj /t:ContainerBuild /p:Configuration=Release
