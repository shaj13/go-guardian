package auth

var ic InfoConstructor

// Info describes a user that has been authenticated to the system.
type Info interface {
	// GetUserName returns the name that uniquely identifies this user among all
	// other active users.
	GetUserName() string
	// SetUserName set the name that uniquely identifies this user among all
	// other active users.
	SetUserName(string)
	// GetID returns a unique value identify a particular user.
	GetID() string
	// SetID set a unique value identify a particular user.
	SetID(string)
	// GetGroups returns the names of the groups the user is a member of
	GetGroups() []string
	// SetGroups set the names of the groups the user is a member of.
	SetGroups(groups []string)
	// Extensions can contain any additional information.
	GetExtensions() Extensions
	// SetExtensions to contain additional information.
	SetExtensions(exts Extensions)
}

// InfoConstructor define function signature to create new Info object.
type InfoConstructor func(name, id string, groups []string, extensions Extensions) Info

// DefaultUser implement Info interface and provides a simple user information.
type DefaultUser struct {
	Name       string
	ID         string
	Groups     []string
	Extensions Extensions
}

// GetUserName returns the name that uniquely identifies this user among all
// other active users.
func (d *DefaultUser) GetUserName() string {
	return d.Name
}

// SetUserName set the name that uniquely identifies this user among all
// other active users.
func (d *DefaultUser) SetUserName(name string) {
	d.Name = name
}

// GetID returns a unique value identify a particular user
func (d *DefaultUser) GetID() string {
	return d.ID
}

// SetID set a unique value identify a particular user.
func (d *DefaultUser) SetID(id string) {
	d.ID = id
}

// GetGroups returns the names of the groups the user is a member of
func (d *DefaultUser) GetGroups() []string {
	return d.Groups
}

// SetGroups set the names of the groups the user is a member of.
func (d *DefaultUser) SetGroups(groups []string) {
	d.Groups = groups
}

// GetExtensions return additional information.
func (d *DefaultUser) GetExtensions() Extensions {
	if d.Extensions == nil {
		d.Extensions = Extensions{}
	}
	return d.Extensions
}

// SetExtensions to contain additional information.
func (d *DefaultUser) SetExtensions(exts Extensions) {
	d.Extensions = exts
}

// NewDefaultUser return new default user
func NewDefaultUser(name, id string, groups []string, extensions Extensions) *DefaultUser {
	return &DefaultUser{
		Name:       name,
		ID:         id,
		Groups:     groups,
		Extensions: extensions,
	}
}

// NewUserInfo implements InfoConstructor and return Info object.
// Typically called from strategies to create a new user object when its authenticated.
func NewUserInfo(name, id string, groups []string, extensions Extensions) Info {
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
