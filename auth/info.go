package auth

var ic InfoConstructor

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
	// SetGroups set the names of the groups the user is a member of.
	SetGroups(groups []string)
	// SetExtensions to contain additional information.
	SetExtensions(exts map[string][]string)
}

// InfoConstructor define function signature to create new Info object.
type InfoConstructor func(name, id string, groups []string, extensions map[string][]string) Info

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

// NewUserInfo implements InfoConstructor and return Info object.
// Typically called from strategies to create a new user object when its authenticated.
func NewUserInfo(name, id string, groups []string, extensions map[string][]string) Info {
	if ic == nil {
		return NewDefaultUser(name, id, groups, extensions)
	}

	return ic(name, id, groups, extensions)
}

// SetInfoConstructor replace the default InfoConstructor
// with any function that has the appropriate signature.
// This allows the developers to create custom user info from their own struct
// instead of using the DefaultUser that go-guardian expose.
//
// Default is NewDefaultUser
func SetInfoConstructor(c InfoConstructor) {
	ic = c
}
