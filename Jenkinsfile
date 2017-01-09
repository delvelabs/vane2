node ('master'){
    stage 'Checkout'
    checkout scm

    stage 'Build'
    sh 'python3.5 -m venv .'
    sh 'bin/pip install --ignore-installed -e git+https://github.com/delvelabs/hammertime.git'
    sh 'bin/pip install --ignore-installed nose'

    stage 'Test'
    sh 'bin/nosetests'
}
