#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0.0-alpine3.14-amd64 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:6.0.100-alpine3.14-amd64 AS build
WORKDIR /src
COPY ["DockerTokenAuthentication/DockerTokenAuthentication.csproj", "DockerTokenAuthentication/"]
RUN dotnet restore "DockerTokenAuthentication/DockerTokenAuthentication.csproj"
COPY . .
WORKDIR "/src/DockerTokenAuthentication"
RUN dotnet build "DockerTokenAuthentication.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "DockerTokenAuthentication.csproj" -c Release -o /app/publish
RUN find /app/publish -type d -exec chmod 0755 {} \;
RUN find /app/publish -type f -exec chmod 0644 {} \;

FROM base AS final
RUN apk add --no-cache icu-libs tzdata libcap; cp /usr/share/zoneinfo/CET /etc/localtime;
RUN setcap 'cap_net_bind_service=+ep' /usr/share/dotnet/dotnet
RUN addgroup -g 1000 -S tokenauth && adduser -u 1000 -S tokenauth -G tokenauth
RUN chown -R tokenauth:tokenauth /app
USER tokenauth
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT false
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
# ENV COMPlus_EnableDiagnostics=0
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "DockerTokenAuthentication.dll"]
