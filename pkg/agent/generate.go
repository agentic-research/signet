package agent

//go:generate sh -c "cd $(dirname $(go env GOMOD)) && protoc --proto_path=. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pkg/agent/api/v1/agent.proto"
