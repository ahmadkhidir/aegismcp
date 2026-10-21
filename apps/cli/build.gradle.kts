plugins {
    application
}

application {
    mainClass.set("dev.aegismcp.cli.AegisCliMain")
    applicationName = "aegis-cli"
}

dependencies {
    implementation(project(":services:gateway"))

    // picocli
    implementation("info.picocli:picocli:4.7.6")
    annotationProcessor("info.picocli:picocli-codegen:4.7.6")

    // Jackson
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.2")

    // Netty
    implementation("io.netty:netty-all:4.1.118.Final")

    // Logging
    implementation("ch.qos.logback:logback-classic:1.5.16")
    implementation("org.slf4j:slf4j-api:2.0.16")

    // Testing
    testImplementation(project(":services:gateway"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
