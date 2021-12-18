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
	pgmockLabel  string = "github.com/win-t/pgmock=true"
	pgPass       string = "pgmock_password"
	templateName string = "mock_template"
	lockID       int64  = 8982324031045737247
)

type Controller struct {
	mu        sync.Mutex
	name      string
	target    *url.URL
	conn      *pgx.Conn
	instances map[string]struct{}
	closed    bool
}

func NewController(ctx context.Context, id string, version int, setup func(connURL, containerName string) error) (*Controller, error) {
	initialized := false

	name := fmt.Sprintf("pgmock-%s", id)
	if err := ensureContainerRunning(ctx, name, version); err != nil {
		return nil, err
	}

	hostPort, err := containerHostPort(ctx, name)
	if err != nil {
		return nil, err
	}

	target := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("postgres", pgPass),
		Host:     hostPort,
		Path:     "postgres",
		RawQuery: "sslmode=disable",
	}

	conn, err := retryConnect(ctx, target.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if !initialized {
			conn.Close(context.Background())
		}
	}()

	if _, err := conn.Exec(ctx, fmt.Sprintf(`select pg_advisory_lock(%d)`, lockID)); err != nil {
		return nil, pgClientError(err, "failed to acquire lock")
	}

	var templateExists bool
	if err := conn.QueryRow(ctx,
		fmt.Sprintf(`select count(datname) = 1 from pg_catalog.pg_database where datname = '%s'`, templateName),
	).Scan(&templateExists); err != nil {
		return nil, pgClientError(err, "cannot query template database information")
	}

	if !templateExists {
		if _, err := conn.Exec(ctx,
			fmt.Sprintf(`create database %s template template0`, templateName),
		); err != nil {
			return nil, pgClientError(err, "cannot create template database")
		}
	}

	if setup != nil {
		if _, err := conn.Exec(ctx,
			fmt.Sprintf(`alter database %s with is_template false allow_connections true`, templateName),
		); err != nil {
			return nil, pgClientError(err, "cannot unlock template database")
		}

		if err := setup(cloneTarget(target, "", "", templateName).String(), name); err != nil {
			return nil, err
		}
	}

	if _, err := conn.Exec(ctx,
		fmt.Sprintf(`alter database %s with is_template true allow_connections false`, templateName),
	); err != nil {
		return nil, pgClientError(err, "cannot lock template database")
	}

	if _, err := conn.Exec(ctx, fmt.Sprintf(`select pg_advisory_unlock(%d)`, lockID)); err != nil {
		return nil, pgClientError(err, "failed to release lock")
	}

	initialized = true
	return &Controller{
		name:      name,
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

	removeContainer(context.Background(), t.name)
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

	t.conn.Close(context.Background())

	t.closed = true
}

func (t *Controller) Instantiate(ctx context.Context) (*Instance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, pgClientError(nil, "template already closed")
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
		`create role %s with login password '%s';`,
		name, name)); err != nil {
		return nil, pgClientError(err, "cannot create role")
	}

	if _, err := t.conn.Exec(ctx, fmt.Sprintf(``+
		`create database %s template %s owner %s;`,
		name, templateName, name)); err != nil {
		return nil, pgClientError(err, "cannot create database")
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
	ctx := context.Background()
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

func ensureContainerRunning(ctx context.Context, name string, version int) error {
	if err := ensureDocker(ctx); err != nil {
		return err
	}
	createContainer(ctx, name, version)
	return startContainer(ctx, name)
}

func ensureDocker(ctx context.Context) error {
	if _, err := exec.CommandContext(ctx, "docker", "info").Output(); err != nil {
		return dockerError(err, "docker is not available")
	}
	return nil
}

func createContainer(ctx context.Context, name string, version int) {
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
		"-e", "POSTGRES_PASSWORD="+pgPass,
		image,
	).Output()
}

func startContainer(ctx context.Context, name string) error {
	_, err := exec.CommandContext(ctx, "docker", "start", name).Output()
	if err != nil {
		return dockerError(err, "cannot start container")
	}
	return nil
}

func removeContainer(ctx context.Context, name string) {
	exec.CommandContext(context.Background(), "docker", "rm", "-fv", name).Output()
}

func containerHostPort(ctx context.Context, name string) (string, error) {
	out, err := exec.CommandContext(ctx,
		"docker", "inspect", name,
		"-f", `{{ with (index (index .NetworkSettings.Ports "5432/tcp") 0) }}{{ .HostIp }}#{{ .HostPort }}{{ end }}`,
	).Output()
	if err != nil {
		return "", dockerError(err, "cannot get host and port of container")
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "#")
	if len(parts) != 2 {
		return "", dockerError(nil, "invalid host and port of container")
	}

	if parts[0] == "0.0.0.0" || parts[0] == "::" {
		parts[0] = "localhost"
	}

	return net.JoinHostPort(parts[0], parts[1]), nil
}

func retryConnect(ctx context.Context, target string) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var (
		c   *pgx.Conn
		err error
	)
	for {
		if c, err = pgx.Connect(ctx, target); err == nil {
			if err = c.Ping(ctx); err == nil {
				return c, nil
			}
		}

		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return nil, pgClientError(err, "timeout when trying to connect")
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

type ErrorType string

const (
	ErrDocker         ErrorType = "docker"
	ErrPostgresClient ErrorType = "postgres-client"
)

type Error struct {
	Type    ErrorType
	Message string
	Cause   error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }

func dockerError(cause error, msg string) error   { return &Error{ErrDocker, msg, cause} }
func pgClientError(cause error, msg string) error { return &Error{ErrPostgresClient, msg, cause} }
