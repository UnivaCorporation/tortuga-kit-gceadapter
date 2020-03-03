#############################################################################
#
# This code is the Property, a Trade Secret and the Confidential Information
# of Univa Corporation.
#
# Copyright 2008-2018 Univa Corporation. All Rights Reserved. Access is Restricted.
#
# It is provided to you under the terms of the
# Univa Term Software License Agreement.
#
# If you have any questions, please contact our Support Department.
#
# http://www.univa.com
#
#############################################################################
import logging
from typing import Optional

from tortuga.events.listeners.base import BaseListener
from tortuga.events.types import (ResourceRequestCreated,
                                  ResourceRequestUpdated,
                                  ResourceRequestDeleted)
from tortuga.exceptions.validationError import ValidationError
from tortuga.resources.types import (get_resource_request_class,
                                     BaseResourceRequest,
                                     ScaleSetResourceRequest)
from tortuga.resources.store import ResourceRequestStore
from tortuga.resources.manager import ResourceRequestStoreManager

from tortuga.resourceAdapter.resourceAdapterFactory import get_api
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter

from sqlalchemy.orm import sessionmaker
from tortuga.web_service.database import dbm

logger = logging.getLogger(__name__)


class GceScaleSetListenerMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._store: ResourceRequestStore = ResourceRequestStoreManager.get()
        Session = sessionmaker(bind=dbm.engine)
        self.session = Session()
        self._adapter_name = 'GCP'

    def get_resource_adapter(self) -> ResourceAdapter:
        adapter = get_api(self._adapter_name)
        adapter.session = self.session
        return adapter

    def is_valid_request(self, resource_request: BaseResourceRequest) -> bool:
        #
        # Only ScaleSetResourceRequests are valid for these listeners
        #
        if not isinstance(resource_request, ScaleSetResourceRequest):
            return False
        #
        # Only requests destined for GCE are valid for these listeners
        #
        if resource_request.resourceadapter_name != self._adapter_name:
            return False
        #
        # If we get this far, then the request is valid
        #
        return True

    def get_scale_set_request(self,
                              event) -> Optional[ScaleSetResourceRequest]:
        #
        # Get the resource request
        #
        rr = self._store.get(event.resourcerequest_id)
        #
        # Validate the resource request
        #
        if not self.is_valid_request(rr):
            return None

        return rr

    def get_previous_scale_set_request(
            self, event) -> Optional[ScaleSetResourceRequest]:
        #
        # Make sure the event has the previous resource request attribute
        #
        if not hasattr(event, 'previous_resourcerequest'):
            return None
        #
        # Deserialize the previous resource request
        #
        rr_data = event.previous_resourcerequest
        resource_request_class = get_resource_request_class(
            rr_data['resource_type'])
        schema_class = resource_request_class.get_schema_class()
        unmarshalled = schema_class().load(event.previous_resourcerequest)
        rr = resource_request_class(**unmarshalled.data)
        #
        # Validate the resource request
        #
        if not self.is_valid_request(rr):
            return None

        return rr


class GceScaleSetCreatedListener(GceScaleSetListenerMixin, BaseListener):
    name = 'gce-scale-set-created-listener'
    event_types = [ResourceRequestCreated]

    def run(self, event: ResourceRequestCreated):
        #
        # If no scale set for GCE, then ignore this event
        #
        ssr = self.get_scale_set_request(event)
        if ssr is None:
            return

        logger.warning('Scale set create request for %s: %s',
                       self._adapter_name, ssr.id)

        # Validate scale set request
        self._validate_scale_set_request(ssr)

        # Load the resource adapter for this request
        try:
            adapter = self.get_resource_adapter()
        except Exception as ex:
            logger.warning('Resource adapter is not installed: %s', ex)
            self._store.delete(ssr.id)
            return

        try:
            # Now create the scale set
            adapter.create_scale_set(
                name=ssr.id,
                resourceAdapterProfile=ssr.resourceadapter_profile_name,
                desiredCount=ssr.desired_nodes,
                hardwareProfile=ssr.hardwareprofile_name,
                softwareProfile=ssr.softwareprofile_name,
                instance_template_name=ssr.instance_template_name,
                adapter_args=ssr.adapter_arguments
            )
        except Exception as ex:
            logger.error("Error creating resource request: %s", ex)
            self._store.delete(ssr.id)
            raise

    def _validate_scale_set_request(self, ssr: ScaleSetResourceRequest):
        err_msg = None
        if ssr.instance_template_name:
            if (ssr.hardwareprofile_name or ssr.softwareprofile_name):
                err_msg = ('Specify either an instance template name or a '
                           'hardware profile and software profile to create a '
                           'scale set, not both.')
        elif not (ssr.hardwareprofile_name and ssr.softwareprofile_name):
            err_msg = ('Must specify both a hardware profile and a software '
                       'profile to create a scale set.')
        elif not ssr.resourceadapter_name:
            err_msg = 'Scale set creation requires a resource adapter name.'
        elif not ssr.resourceadapter_profile_name:
            err_msg = ('Scale set creation requires a resource adapter '
                       'profile name.')

        if err_msg:
            raise ValidationError(err_msg)


class GceScaleSetUpdatedListener(GceScaleSetListenerMixin, BaseListener):
    name = 'gce-scale-set-updated-listener'
    event_types = [ResourceRequestUpdated]

    def run(self, event: ResourceRequestUpdated):
        #
        # If no scale set for GCE, then ignore this event
        #
        ssr = self.get_scale_set_request(event)
        if ssr is None:
            return

        logger.warning('Scale set update request for %s: %s',
                       self._adapter_name, ssr.id)

        # Load the resource adapter for this request
        try:
            adapter = self.get_resource_adapter()
        except Exception as ex:
            logger.warning('Resource adapter is not installed: %s', ex)
            return

        try:
            # Now create the scale set
            adapter.update_scale_set(
                name=ssr.id,
                resourceAdapterProfile=ssr.resourceadapter_profile_name,
                desiredCount=ssr.desired_nodes,
                adapter_args=ssr.adapter_arguments
            )
        except Exception as ex:
            logger.error("Error updating resource request: %s", ex)
            old = self.get_previous_scale_set_request(event)
            self._store.rollback(old)


class GceScaleSetDeletedListener(GceScaleSetListenerMixin, BaseListener):
    name = 'gce-scale-set-deleted-listener'
    event_types = [ResourceRequestDeleted]

    def run(self, event: ResourceRequestDeleted):
        #
        # If no scale set for GCE, then ignore this event
        #
        ssr = self.get_previous_scale_set_request(event)
        if ssr is None:
            return

        logger.warning('Scale set delete request for %s: %s',
                       self._adapter_name, ssr.id)

        # Load the resource adapter for this request
        try:
            adapter = self.get_resource_adapter()
        except Exception as ex:
            logger.warning('Resource adapter is not installed: %s', ex)
            return

        # Now create the scale set
        try:
            adapter.delete_scale_set(
                name=ssr.id,
                resourceAdapterProfile=ssr.resourceadapter_profile_name,
                adapter_args=ssr.adapter_arguments
            )
        except Exception as ex:
            logger.error("Error deleting resource request: %s", ex)
            self._store.rollback(ssr)
