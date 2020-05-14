package auth

// Info describes a user that has been authenticated to the system.
type Info interface {
	// UserName returns the name that uniquely identifies this user among all
	// other active users.
	UserName() string
	// ID returns a unique value identify a particular user
	ID() string
	// Groups returns the names of the groups the user is a member of
	Groups() []string
	// Extensions can contain any additional information.
	Extensions() map[string][]string
}

// DefaultUser implement Info interface and provides a simple user information.
type DefaultUser struct {
	name       string
	id         string
	groups     []string
	extensions map[string][]string
}

// UserName returns the name that uniquely identifies this user among all
// other active users.
func (d *DefaultUser) UserName() string {
	return d.name
}

// ID returns a unique value identify a particular user
func (d *DefaultUser) ID() string {
	return d.id
}

// Groups returns the names of the groups the user is a member of
func (d *DefaultUser) Groups() []string {
	return d.groups
}

// SetGroups set the names of the groups the user is a member of.
func (d *DefaultUser) SetGroups(groups []string) {
	d.groups = groups
}

// Extensions return additional information.
func (d *DefaultUser) Extensions() map[string][]string {
	return d.extensions
}

// SetExtensions to contain additional information.
func (d *DefaultUser) SetExtensions(exts map[string][]string) {
	d.extensions = exts
}

// NewDefaultUser return new default user
func NewDefaultUser(name, id string, groups []string, extensions map[string][]string) *DefaultUser {
	return &DefaultUser{
		name:       name,
		id:         id,
		groups:     groups,
		extensions: extensions,
	}
}
