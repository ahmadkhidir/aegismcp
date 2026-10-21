plugins {
    `java-library`
}

dependencies {
    implementation(project(":services:gateway"))
    implementation(project(":apps:cli"))

    // Netty 4.1
    implementation("io.netty:netty-all:4.1.118.Final")

    // Jackson 2.17
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.2")

    // Picocli
    implementation("info.picocli:picocli:4.7.6")

    // Logging
    implementation("ch.qos.logback:logback-classic:1.5.16")
    implementation("org.slf4j:slf4j-api:2.0.16")

    // Testing
    testImplementation(project(":services:gateway"))
    testImplementation(project(":apps:cli"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
