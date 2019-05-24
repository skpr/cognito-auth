package config


type AwsCredentials struct {
	AccessKey    string `yaml:"access_key"`
	AccessSecret string `yaml:"access_secret"`
	SessionToken string `yaml:"session_token"`
}

