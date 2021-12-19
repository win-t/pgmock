package pgmock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v4"
)

const (
	pgmockLabel    string = "github.com/win-t/pgmock=true"
	mockIdentifier string = "mock"
	lockID         int64  = 8982324031045737247
)

var ctx = context.Background()

type Controller struct {
	mu        sync.Mutex
	name      string
	target    *url.URL
	conn      *pgx.Conn
	instances map[string]struct{}
	closed    bool
}

func NewController(containerName string, postgresMajorVersion int, setup func(firstRun bool, connURL string) error) (*Controller, error) {
	if containerName == "" {
		panic("pgmock: containerName cannot be empty string")
	}

	initialized := false

	if err := ensureContainerRunning(containerName, postgresMajorVersion); err != nil {
		return nil, err
	}

	hostPort, err := containerHostPort(containerName)
	if err != nil {
		return nil, err
	}

	target := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("postgres", mockIdentifier),
		Host:     hostPort,
		Path:     "postgres",
		RawQuery: "sslmode=disable",
	}

	conn, err := retryConnect(target.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if !initialized {
			conn.Close(ctx)
		}
	}()

	if _, err := conn.Exec(ctx, fmt.Sprintf(`select pg_advisory_lock(%d)`, lockID)); err != nil {
		return nil, fmt.Errorf("failed to acquire lock")
	}

	var templateExists bool
	if err := conn.QueryRow(ctx,
		fmt.Sprintf(`select count(datname) = 1 from pg_catalog.pg_database where datname = '%s'`, mockIdentifier),
	).Scan(&templateExists); err != nil {
		return nil, fmt.Errorf("cannot query template database information")
	}

	if !templateExists {
		if _, err := conn.Exec(ctx,
			fmt.Sprintf(`create role %s with login password '%s';`, mockIdentifier, mockIdentifier),
		); err != nil {
			return nil, fmt.Errorf("cannot create template role")
		}

		if _, err := conn.Exec(ctx,
			fmt.Sprintf(`create database %s template template0`, mockIdentifier),
		); err != nil {
			return nil, fmt.Errorf("cannot create template database")
		}
	}

	if setup != nil {
		if _, err := conn.Exec(ctx,
			fmt.Sprintf(`alter database %s with is_template false allow_connections true`, mockIdentifier),
		); err != nil {
			return nil, fmt.Errorf("cannot unlock template database")
		}

		if err := setup(!templateExists, cloneTarget(target, mockIdentifier, mockIdentifier, mockIdentifier).String()); err != nil {
			return nil, err
		}
	}

	if _, err := conn.Exec(ctx,
		fmt.Sprintf(`alter database %s with is_template true allow_connections false`, mockIdentifier),
	); err != nil {
		return nil, fmt.Errorf("cannot lock template database")
	}

	if _, err := conn.Exec(ctx, fmt.Sprintf(`select pg_advisory_unlock(%d)`, lockID)); err != nil {
		return nil, fmt.Errorf("failed to release lock")
	}

	initialized = true
	return &Controller{
		name:      containerName,
		target:    target,
		conn:      conn,
		instances: make(map[string]struct{}),
	}, nil
}

func (t *Controller) DestroyContainer() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return
	}

	t.close_Locked()

	removeContainer(t.name)
}

func (t *Controller) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.close_Locked()
}

func (t *Controller) close_Locked() {
	if t.closed {
		return
	}

	var names []string
	for name := range t.instances {
		names = append(names, name)
	}

	for _, name := range names {
		t.destoryInstance_Locked(name)
	}

	t.conn.Close(ctx)

	t.closed = true
}

func (t *Controller) Instantiate() (*Instance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, fmt.Errorf("template already closed")
	}

	initialized := false

	var name string
	for {
		var random [16]byte
		for {
			if _, err := rand.Read(random[:]); err == nil {
				break
			}
		}
		name = strings.ToLower(fmt.Sprintf("mock_%s", hex.EncodeToString(random[:])))
		if _, ok := t.instances[name]; !ok {
			break
		}
	}

	defer func() {
		if !initialized {
			t.destoryInstance_Locked(name)
		}
	}()

	if _, err := t.conn.Exec(ctx, fmt.Sprintf(``+
		`create role %s with login password '%s' in role %s;`,
		name, name, mockIdentifier)); err != nil {
		return nil, fmt.Errorf("cannot create role")
	}

	if _, err := t.conn.Exec(ctx, fmt.Sprintf(``+
		`create database %s template %s owner %s;`,
		name, mockIdentifier, name)); err != nil {
		return nil, fmt.Errorf("cannot create database")
	}

	t.instances[name] = struct{}{}

	initialized = true
	return &Instance{
		t:       t,
		name:    name,
		connURL: cloneTarget(t.target, name, name, name).String(),
	}, nil
}

func (t *Controller) destoryInstance(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.destoryInstance_Locked(name)
}

func (t *Controller) destoryInstance_Locked(name string) {
	t.conn.Exec(ctx, fmt.Sprintf(`drop database %s with (force)`, name))
	t.conn.Exec(ctx, fmt.Sprintf(`drop role %s`, name))
	delete(t.instances, name)
}

type Instance struct {
	t       *Controller
	name    string
	connURL string
}

func (i *Instance) ConnURL() string {
	return i.connURL
}

func (i *Instance) Destroy() {
	i.t.destoryInstance(i.name)
}

func ensureContainerRunning(name string, version int) error {
	createContainer(name, version)
	return startContainer(name)
}

func createContainer(name string, version int) {
	image := "postgres:alpine"
	if version != 0 {
		image = fmt.Sprintf("postgres:%d-alpine", version)
	}
	exec.CommandContext(ctx,
		"docker", "create",
		"--name", name,
		"--restart", "unless-stopped",
		"-l", pgmockLabel,
		"-p", "5432",
		"-e", "POSTGRES_PASSWORD="+mockIdentifier,
		image,
	).Output()
}

func startContainer(name string) error {
	_, err := exec.CommandContext(ctx, "docker", "start", name).Output()
	if err != nil {
		return fmt.Errorf("cannot start container")
	}
	return nil
}

func removeContainer(name string) {
	exec.CommandContext(ctx, "docker", "rm", "-fv", name).Output()
}

func containerHostPort(name string) (string, error) {
	out, err := exec.CommandContext(ctx,
		"docker", "inspect", name,
		"-f", `{{ with (index (index .NetworkSettings.Ports "5432/tcp") 0) }}{{ .HostIp }}#{{ .HostPort }}{{ end }}`,
	).Output()
	if err != nil {
		return "", fmt.Errorf("cannot get host and port of container")
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "#")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid host and port of container")
	}

	if parts[0] == "0.0.0.0" || parts[0] == "::" {
		parts[0] = "localhost"
	}

	return net.JoinHostPort(parts[0], parts[1]), nil
}

func retryConnect(target string) (*pgx.Conn, error) {
	retryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var (
		c   *pgx.Conn
		err error
	)
	for {
		if c, err = pgx.Connect(retryCtx, target); err == nil {
			if err = c.Ping(retryCtx); err == nil {
				return c, nil
			}
		}

		select {
		case <-time.After(100 * time.Millisecond):
		case <-retryCtx.Done():
			return nil, fmt.Errorf("timeout when trying to connect")
		}
	}
}

func cloneTarget(old *url.URL, user, pass, db string) *url.URL {
	new := &url.URL{}
	*new = *old
	if db != "" {
		new.Path = db
	}
	if user != "" || pass != "" {
		new.User = url.UserPassword(user, pass)
	}
	return new
}

func DockerAvailable() bool {
	_, err := exec.CommandContext(ctx, "docker", "info").Output()
	return err == nil
}
