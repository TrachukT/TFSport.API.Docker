#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

#Depending on the operating system of the host machines(s) that will build or run the containers, the image specified in the FROM statement may need to be changed.
#For more information, please see https://aka.ms/containercompat

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["TRSPO_Project.Users/TRSPO_Project.Users.csproj", "TRSPO_Project.Users/"]
COPY ["TFSport.Models/TFSport.Models.csproj", "TFSport.Models/"]
COPY ["TFSport.Repository/TFSport.Repository.csproj", "TFSport.Repository/"]
COPY ["TFSport.Services/TFSport.Services.csproj", "TFSport.Services/"]
RUN dotnet restore "./TRSPO_Project.Users/TRSPO_Project.Users.csproj"
COPY . .
WORKDIR "/src/TRSPO_Project.Users"
RUN dotnet build "./TRSPO_Project.Users.csproj" -c %BUILD_CONFIGURATION% -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./TRSPO_Project.Users.csproj" -c %BUILD_CONFIGURATION% -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
COPY ./TRSPO_Project.Users/emulatorcert.crt /usr/local/share/ca-certificates/
RUN chmod 644 /usr/local/share/ca-certificates/emulatorcert.crt && update-ca-certificates
ENTRYPOINT ["dotnet", "TRSPO_Project.Users.dll"]