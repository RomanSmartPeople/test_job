from django.views.generic import TemplateView
from django.template.context import RequestContext
from django.shortcuts import render_to_response, render
from django.contrib.auth import logout, get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_social_auth.serializers import UserSerializer
from rest_social_auth.views import JWTAuthMixin
from oauth2client.client import flow_from_clientsecrets
from oauth2client.contrib.django_util.storage import DjangoORMStorage as Storage
from django.contrib.auth.decorators import login_required
from .models import CredentialsModel
from oauth2client.contrib import xsrfutil
from django.conf import settings
from django.http import HttpResponseRedirect
import httplib2
from django.contrib.auth.models import User
from apiclient.discovery import build
from apiclient import errors


CLIENT_SECRETS = 'users/client_secret.json'

FLOW = flow_from_clientsecrets(
    CLIENT_SECRETS,
    scope='https://www.googleapis.com/auth/gmail.readonly',
    redirect_uri='http://localhost:8000/z2/')


class HomeSessionView(TemplateView):
    template_name = 'home_session.html'

    @method_decorator(ensure_csrf_cookie)
    def get(self, request, *args, **kwargs):
        return super(HomeSessionView, self).get(request, *args, **kwargs)


class HomeTokenView(TemplateView):
    template_name = 'home_token.html'


class HomeJWTView(TemplateView):
    template_name = 'home_jwt.html'


class LogoutSessionView(APIView):

    def post(self, request, *args, **kwargs):
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class BaseDetailView(generics.RetrieveAPIView):
    permission_classes = IsAuthenticated,
    serializer_class = UserSerializer
    model = get_user_model()

    def get_object(self, queryset=None):
        return self.request.user


class UserSessionDetailView(BaseDetailView):
    authentication_classes = (SessionAuthentication, )


class UserTokenDetailView(BaseDetailView):
    authentication_classes = (TokenAuthentication, )


class UserJWTDetailView(JWTAuthMixin, BaseDetailView):
    pass


@login_required
def emails_list(request):
    storage = Storage(CredentialsModel, 'id', request.user, 'credential')
    credential = storage.get()
    if credential is None or credential.invalid == True:
        FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY,
                                                   request.user)
        authorize_url = FLOW.step1_get_authorize_url()
        return HttpResponseRedirect(authorize_url)
    else:
        http = httplib2.Http()
        http = credential.authorize(http)
        service = build("gmail", "v1", http=http)
        msg_list_id = ListMessagesMatchingQuery(service, 'me')
        msg_list = []
        for i in msg_list_id[:100]:
            msg = GetMessage(service, 'me', i[u'id'])
            msg_list.append(msg['snippet'])
        return render(request, 'emails_list.html', {
                    'msg_list': msg_list,
                    })

@login_required
def z2(request):
  # if not xsrfutil.validate_token(settings.SECRET_KEY, request.GET['state'],
  #                                request.user):
  #   return  HttpResponseBadRequest()
    credential = FLOW.step2_exchange(request.GET)
    storage = Storage(CredentialsModel, 'id', request.user, 'credential')
    storage.put(credential)
    return HttpResponseRedirect("/emails")


def ListMessagesMatchingQuery(service, user_id, query=''):
    try:
        response = service.users().messages().list(userId=user_id,
                                                   q=query).execute()
        messages = []
        if 'messages' in response:
            messages.extend(response['messages'])

        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(userId=user_id, q=query,
                                             pageToken=page_token).execute()
            messages.extend(response['messages'])

        return messages
    except errors.HttpError, error:
        print 'An error occurred: %s' % error

def GetMessage(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()
        return message
    except errors.HttpError, error:
        print 'An error occurred: %s' % error