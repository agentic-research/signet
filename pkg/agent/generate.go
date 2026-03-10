package agent

//go:generate sh -c "cd $GOPATH/src/github.com/agentic-research/signet && protoc --proto_path=. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pkg/agent/api/v1/agent.proto"
