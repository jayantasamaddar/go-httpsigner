test:
	go test -v -race -cover -coverprofile=.coverage.out ./...

test-report:
	go tool cover -func=.coverage.out && go tool cover -html=.coverage.out -o coverage.html

clean:
	rm -rf .coverage.out coverage.html