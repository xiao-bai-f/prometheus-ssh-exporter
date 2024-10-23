package utils

import (
	"golang.org/x/crypto/ssh"
	"log"
	"os"
)

type SshConfig struct {
	Target         string
	User           string
	Password       string
	PrivateKeyPath string
}

type SshClient struct {
	Client  *ssh.Client
	Session *ssh.Session
}

type Result struct {
	output []byte
	err    error
}

func NewSshClient(sshConfig SshConfig) (*SshClient, error) {
	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if sshConfig.User != "" {
		config.User = sshConfig.User
	}
	if sshConfig.PrivateKeyPath != "" {
		// 通过密钥
		privateKey, err := os.ReadFile(sshConfig.PrivateKeyPath)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		// 解析私钥
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	}

	if sshConfig.Password != "" {
		// 通过密码
		config.Auth = []ssh.AuthMethod{
			ssh.Password(sshConfig.Password),
		}
	}

	client, err := ssh.Dial("tcp", sshConfig.Target, config)
	if err != nil {
		log.Println("failed to dail:", err)
		return nil, err
	}

	return &SshClient{
		Client: client,
	}, nil

}

func (sshClient *SshClient) newSession() error {
	session, err := sshClient.Client.NewSession()
	if err != nil {
		log.Println("Failed to create session: ", err)
		return err
	}

	sshClient.Session = session
	return nil
}

func (sshClient *SshClient) ExecCommand(command string) (string, error) {

	if sshClient.Session == nil {
		err := sshClient.newSession()
		if err != nil {
			return "", err
		}
	}

	output, err := sshClient.Session.CombinedOutput(command)
	if err != nil {
		return "", err
	}

	return string(output), err

}

func (sshClient *SshClient) Close() {

	err := sshClient.Client.Close()
	if err != nil {
		log.Println("ssh client close failed")
		return
	}

}
