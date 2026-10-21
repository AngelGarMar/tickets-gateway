# --- ETAPA 1: BUILD (construcción) ---
FROM maven:3.9.12-eclipse-temurin-25-alpine AS builder
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

# --- ETAPA 2: RUNTIME (construcción final) ---
FROM eclipse-temurin:25-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar gateway.jar
ENTRYPOINT ["java", "-jar", "gateway.jar"]