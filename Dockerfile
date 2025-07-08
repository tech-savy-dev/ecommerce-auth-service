# Use a lightweight JDK 21 base image
FROM eclipse-temurin:21-jdk-alpine as builder
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
