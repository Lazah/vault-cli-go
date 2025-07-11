package internal

import (
	"fmt"
	"sync"

	"github.com/Lazah/vault-cli-go/internal/vault"
)

func ListSecrets() {
	client, err := vault.NewClient("http://localhost:8200/")
	if err != nil {
		fmt.Println(err.Error())
	}
	err = client.WithUserAuth("", "", "")
	if err != nil {
		fmt.Println(err.Error())
	}
	err = client.Authenticate()
	if err != nil {
		fmt.Println(err.Error())
	}
	resultChan := make(chan string, 100)
	folderChan := make(chan string, 100)
	folderGroup := new(sync.WaitGroup)
	folderChan <- ""
	folderGroup.Add(2)
	vault.StartPathHandlers(resultChan, folderChan, "secret", client, folderGroup)
	go func() {
		folderGroup.Wait()
		close(folderChan)
		close(resultChan)
	}()
	paths := make([]string, 0)
	for result := range resultChan {
		paths = append(paths, result)
	}

	fmt.Println("paths:")
	for _, v := range paths {
		fmt.Println(v)
	}

}
