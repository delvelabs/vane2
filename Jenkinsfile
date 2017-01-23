node ('master'){
    stage 'Checkout'
    checkout scm

    stage 'Build'
    sh 'python3.5 -m venv .'
    sh 'bin/pip install -r requirements.txt'
    sh 'bin/pip install --ignore-installed -e git+https://github.com/delvelabs/hammertime.git#egg=hammertime'
    sh 'bin/pip install --ignore-installed nose'
    sh 'bin/pip install --ignore-installed -e git+ssh://git@bitbucket.org/delvelabs/openwebvulndb-tools.git@WRN-1097#egg=openwebvulndb-tools'

    stage 'Test'
    sh 'bin/nosetests'
}
