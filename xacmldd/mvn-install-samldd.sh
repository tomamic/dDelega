#!/bin/bash
mvn install:install-file -DgroupId=ddelega -DartifactId=samldd -Dpackaging=jar -Dversion=1.0-SNAPSHOT -DgeneratePom=true -Dfile=../samldd/target/samldd-1.0-SNAPSHOT.jar
