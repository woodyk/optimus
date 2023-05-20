def gv

pipeline {
    agent any
    stages {
        stage('git clone') {
            steps {
                git branch: 'main', url: 'https://github.com/woodyk/optimus.git'
            }
        }
        stage('docker setup') {
            steps {
                sh 'docker build -t optimus .'
                sh 'docker run -d --rm -p 8000:8000 -p 4430:4430 -e OPTIMUS_ARGS=\'--dummy\' --name=optimus_api optimus'
            }
        }
        stage('test optimus') {
            steps {
                sh 'curl -F \'upload=@lib/examples/test.pcap\' http://localhost:8000'
            }
        }
        stage('clean up') {
            steps {
                sh 'docker stop optimus_api'
                sh 'docker rmi optimus ubuntu'
            }
        }
    }
}