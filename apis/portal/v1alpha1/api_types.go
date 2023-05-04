/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// APIParameters are the configurable fields of a API.
type APIParameters struct {
	ConfigurableField string `json:"configurableField"`
}

// APIObservation are the observable fields of a API.
type APIObservation struct {
	ObservableField string `json:"observableField,omitempty"`
}

// A APISpec defines the desired state of a API.
type APISpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       APIParameters `json:"forProvider"`
}

// A APIStatus represents the observed state of a API.
type APIStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          APIObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A API is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,layer7}
type API struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APISpec   `json:"spec"`
	Status APIStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIList contains a list of API
type APIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []API `json:"items"`
}

// API type metadata.
var (
	APIKind             = reflect.TypeOf(API{}).Name()
	APIGroupKind        = schema.GroupKind{Group: Group, Kind: APIKind}.String()
	APIKindAPIVersion   = APIKind + "." + SchemeGroupVersion.String()
	APIGroupVersionKind = SchemeGroupVersion.WithKind(APIKind)
)

func init() {
	SchemeBuilder.Register(&API{}, &APIList{})
}
