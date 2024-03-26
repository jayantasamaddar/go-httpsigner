package utils

import (
	"bufio"
	"log"
	"os"
	"os/user"
	"strings"

	"github.com/go-ini/ini"
)

// Get the path to the Home Directory, irrespective of underlying operating system
func HomeDir() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	return currentUser.HomeDir, nil
}

// Struct representing the contents of a config file as a
//
//	Profile.Name
//
// and the Keys and values in a map,
//
//	Profile.Map
type Profile struct {
	Name string
	Map  map[string]string
}

// Function to read .ini file and return a `Profile`
func ReadIniFile(filename string) <-chan *Profile {
	out := make(chan *Profile)
	go func() {
		defer close(out)

		cfg, err := ini.Load(filename)
		if err != nil {
			log.Printf("Failed to load INI file %s: %v", filename, err)
			return
		}

		for _, section := range cfg.Sections() {
			name := section.Name()
			sectionMap := make(map[string]string)

			keys := section.Keys()
			for _, key := range keys {
				sectionMap[key.Name()] = key.String()
			}

			out <- &Profile{
				Name: name,
				Map:  sectionMap,
			}
		}
	}()
	return out
}

// Function to read .env file and return a `Profile`
func ReadEnvFile(filename string) (*Profile, error) {
	profile := Profile{
		Name: "default",
		Map:  make(map[string]string),
	}

	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Failed to open file %s: %v", filename, err)
		return &profile, err
	}
	defer file.Close()

	// Read lines from the file
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			profile.Map[key] = value
		}
	}
	err = scanner.Err()
	return &profile, err
}
