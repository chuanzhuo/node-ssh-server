exports.magic = {
    kexinit : 20,
};

exports.algorithms = [
    {
        key : 'kex_algorithms',
        names : [ 'diffie-hellman-group1-sha1' ],
    },
    {
        key : 'server_host_key_algorithms',
        names : [ 'ssh-dss' ],
    },
    {
        key : 'encryption_algorithms_client_to_server',
        names : [ 'aes-128-cbc' ],
    },
    {
        key : 'encryption_algorithms_server_to_client',
        names : [],
    },
    {
        key : 'mac_algorithms_client_to_server',
        names : [ 'sha1', 'md5' ],
    },
    {
        key : 'mac_algorithms_server_to_client',
        names : [],
    },
    {
        key : 'compression_algorithms_client_to_server',
        names : [],
    },
    {
        key : 'compression_algorithms_server_to_client',
        names : [],
    },
    {
        key : 'languages_client_to_server',
        names : [],
    },
    {
        key : 'languages_server_to_client',
        names : [],
    },
];
