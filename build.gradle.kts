import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.1.20"
    `java-library`
    `maven-publish`
}

group = "id.wolin"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xjdk-release=17")
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifactId = "sdk-kotlin"
            pom {
                name.set("Wolin Kotlin SDK")
                description.set(
                    "Official zero-dependency Kotlin/Android/JVM SDK for Wolin (月印千江) Sovereign Solid Pods (Solid-OIDC, RFC 9449 DPoP ES256, WebID, LDP CRUD)"
                )
                url.set("https://wolin.id")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                organization {
                    name.set("Entropy Paradox, Inc.")
                    url.set("https://wolin.id")
                }
                developers {
                    developer {
                        id.set("wolin-id")
                        name.set("Entropy Paradox, Inc.")
                        url.set("https://wolin.id")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/wolin-id/sdk-kotlin.git")
                    developerConnection.set("scm:git:ssh://git@github.com/wolin-id/sdk-kotlin.git")
                    url.set("https://github.com/wolin-id/sdk-kotlin")
                }
            }
        }
    }
}
