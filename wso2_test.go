package wso2_test

import (
	"os"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/markbates/goth"
	"github.com/rzrbld/goth/providers/wso2"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("WSO2_KEY"))
	a.Equal(p.Secret, os.Getenv("WSO2_SECRET"))
	a.Equal(p.Domain, os.Getenv("WSO2_DOMAIN"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*wso2.Session)
	a.NoError(err)
	expectedAuthURL := "https://" + os.Getenv("WSO2_DOMAIN") + "/authorize"
	a.Contains(s.AuthURL, expectedAuthURL)
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	sessionResp := `{"AuthURL":"https://` + p.Domain + `/oauth/authorize","AccessToken":"1234567890"}`
	session, err := p.UnmarshalSession(sessionResp)
	a.NoError(err)

	s := session.(*wso2.Session)
	expectedAuthURL := "https://" + os.Getenv("WSO2_DOMAIN") + "/oauth/authorize"
	a.Equal(s.AuthURL, expectedAuthURL)
	a.Equal(s.AccessToken, "1234567890")
}

func Test_FetchUser(t *testing.T) {
	//t.Parallel()
	a := assert.New(t)

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	sampleResp := `{
  		"email_verified": false,
  		"email": "test.account@userinfo.com",
  		"clientID": "q2hnj2iu...",
  		"updated_at": "2016-12-05T15:15:40.545Z",
  		"name": "test.account@userinfo.com",
  		"picture": "https://s.gravatar.com/avatar/dummy.png",
  		"user_id": "wso2|58454...",
  		"nickname": "test.account",
  		"identities": [
  		  {
      			"user_id": "58454...",
      			"provider": "wso2",
      			"connection": "Username-Password-Authentication",
      			"isSocial": false
    		}],
  		"created_at": "2016-12-05T11:16:59.640Z",
  		"sub": "wso2|58454..."
	}`

	httpmock.RegisterResponder("GET", "https://"+os.Getenv("WSO2_DOMAIN")+"/userinfo", httpmock.NewStringResponder(200, sampleResp))

	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*wso2.Session)
	s.AccessToken = "token"
	u, err := p.FetchUser(s)
	a.Nil(err)
	a.Equal(u.Email, "test.account@userinfo.com")
	a.Equal(u.UserID, "wso2|58454...")
	a.Equal(u.NickName, "test.account")
	a.Equal(u.Name, "test.account@userinfo.com")
	a.Equal("token", u.AccessToken)

}

func provider() *wso2.Provider {
	return wso2.New(os.Getenv("WSO2_KEY"), os.Getenv("WSO2_SECRET"), "/foo", os.Getenv("WSO2_DOMAIN"))
}
