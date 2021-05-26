#!/usr/bin/env groovy

pipeline {

  agent {
    kubernetes {
      yamlFile 'JenkinsPod.yaml'
      defaultContainer 'kaniko'
    }
  }

  options {
    timestamps()
  }

  stages {
    stage('Build') {
      steps {
        script {
          sh "/kaniko/executor -c `pwd` --cache=true --destination=eu.gcr.io/si-valeuriad-310607/snipe-it:${env.BRANCH_NAME}"
        }
      }
    }
  }
}
