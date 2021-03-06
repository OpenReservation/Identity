FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine AS base
RUN apk add icu-libs
# https://www.abhith.net/blog/docker-sql-error-on-aspnet-core-alpine/
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT false
EXPOSE 80

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-alpine AS build
WORKDIR /src
COPY ["src/Skoruba.IdentityServer4.STS.Identity/Skoruba.IdentityServer4.STS.Identity.csproj", "src/Skoruba.IdentityServer4.STS.Identity/"]
COPY ["src/Skoruba.IdentityServer4.Admin.EntityFramework.Identity/Skoruba.IdentityServer4.Admin.EntityFramework.Identity.csproj", "src/Skoruba.IdentityServer4.Admin.EntityFramework.Identity/"]
COPY ["src/Skoruba.IdentityServer4.Admin.EntityFramework/Skoruba.IdentityServer4.Admin.EntityFramework.csproj", "src/Skoruba.IdentityServer4.Admin.EntityFramework/"]
COPY ["src/Skoruba.IdentityServer4.Admin.EntityFramework.Extensions/Skoruba.IdentityServer4.Admin.EntityFramework.Extensions.csproj", "src/Skoruba.IdentityServer4.Admin.EntityFramework.Extensions/"]
COPY ["src/Skoruba.IdentityServer4.Admin.EntityFramework.Shared/Skoruba.IdentityServer4.Admin.EntityFramework.Shared.csproj", "src/Skoruba.IdentityServer4.Admin.EntityFramework.Shared/"]
COPY ["src/Skoruba.IdentityServer4.Admin.EntityFramework.SqlServer/Skoruba.IdentityServer4.Admin.EntityFramework.SqlServer.csproj", "src/Skoruba.IdentityServer4.Admin.EntityFramework.SqlServer/"]
COPY ["src/Skoruba.IdentityServer4.Shared/Skoruba.IdentityServer4.Shared.csproj", "src/Skoruba.IdentityServer4.Shared/"]
RUN dotnet restore "src/Skoruba.IdentityServer4.STS.Identity/Skoruba.IdentityServer4.STS.Identity.csproj"
COPY . .
WORKDIR "/src/src/Skoruba.IdentityServer4.STS.Identity"
RUN dotnet publish "Skoruba.IdentityServer4.STS.Identity.csproj" -c Release -o /app/out

FROM base AS final
WORKDIR /app

COPY --from=build /app/out .

ENTRYPOINT ["dotnet", "Skoruba.IdentityServer4.STS.Identity.dll"]