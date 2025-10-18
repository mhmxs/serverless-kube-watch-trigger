/*
Copyright 2025.

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

package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-openapi/inflect"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.sio/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triggersv1 "github.com/mhmxs/serverless-kube-watch-trigger/api/v1"
)

const (
	// LastResourceVersionConfigMapName is the name of the ConfigMap used to store the last processed resource version.
	// This ConfigMap will be created in the same namespace as the HTTPTrigger resource.
	LastResourceVersionConfigMapName = "httptrigger-last-resource-version"
	// ResourceVersionKey is the key within the ConfigMap's Data field that stores the resource version.
	ResourceVersionKey = "lastResourceVersion"
)

type Watcher struct {
	Reconciler *HTTPTriggerReconciler
}

func (w *Watcher) Start(ctx context.Context) error {
	// r.ctx is the main controller context, used for overall controller lifecycle.
	// The individual watchers (goroutines) will derive their contexts from this.
	// WatchInit is currently not used, the watchers are created per HTTPTrigger in Reconcile.
	// This function might be vestigial or intended for a global watch, but the current design
	// creates per-trigger watchers. We'll leave it as is for now as it's not the focus of this refinement.
	return nil // Or return an error if WatchInit is truly not used.
}

// HTTPTriggerReconciler reconciles a HTTPTrigger object
type HTTPTriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient

	ctx                 context.Context // Controller's main context
	runningTriggersLock sync.Mutex
	runningTriggers     map[string]func() // map[namespace/name]cancelFunc
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;create;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// It handles creation, update, and deletion of HTTPTrigger resources.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *HTTPTriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx).WithValues("controller", "httptrigger", "name", req.NamespacedName)

	trigger := triggersv1.HTTPTrigger{}
	if err := r.Get(ctx, req.NamespacedName, &trigger); err != nil {
		if apierrors.IsNotFound(err) {
			// Object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup,
			// refer to the documentation for controller-runtime.
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		logger.Error(err, "Failed to get HTTPTrigger")
		return ctrl.Result{}, err
	}

	r.runningTriggersLock.Lock()
	defer r.runningTriggersLock.Unlock()

	// Handle deletion of the HTTPTrigger resource
	if trigger.DeletionTimestamp != nil && !trigger.DeletionTimestamp.IsZero() {
		logger.Info("HTTPTrigger deleted, stopping associated watcher")

		if cancel, ok := r.runningTriggers[req.String()]; ok {
			cancel() // Stop the running watcher goroutine
			delete(r.runningTriggers, req.String())
		}

		// No finalizer logic needed here as per original code.
		return ctrl.Result{}, nil
	}

	// Log creation or update
	if trigger.Generation == 1 {
		logger.Info("HTTPTrigger created")
	} else {
		logger.Info("HTTPTrigger updated")
	}

	// Create or recreate the watcher for this HTTPTrigger
	if err := r.createTrigger(&trigger); err != nil {
		logger.Error(err, "Failed to initialize/update HTTPTrigger watcher")
		// Update status with error if watcher creation fails
		r.UpdateTriggerStatusWithError(ctx, &trigger, fmt.Sprintf("failed to initialize watcher: %v", err))
		return ctrl.Result{}, err
	}

	// Update the HTTPTrigger status to clear any previous errors
	patchedTrigger := trigger.DeepCopy()
	patchedTrigger.Status.ErrorReason = ""
	// The LastResourceVersion is now managed in a ConfigMap, so we no longer update it in the CR's status.
	// patchedTrigger.Status.LastResourceVersion = "0"

	if err := r.Patch(ctx, patchedTrigger, client.MergeFrom(&trigger)); err != nil {
		if apierrors.IsNotFound(err) {
			// HTTPTrigger may have been deleted while patching status, no need to requeue.
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to update HTTPTrigger status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// getLastResourceVersion retrieves the last processed resource version from a ConfigMap
// in the specified namespace. If the ConfigMap doesn't exist, it creates it with "0".
func (r *HTTPTriggerReconciler) getLastResourceVersion(ctx context.Context, namespace string) (string, error) {
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: LastResourceVersionConfigMapName, Namespace: namespace}, configMap)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Create the ConfigMap if it doesn't exist
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      LastResourceVersionConfigMapName,
					Namespace: namespace,
				},
				Data: map[string]string{
					ResourceVersionKey: "0", // Initialize with "0" to start watching from the beginning
				},
			}
			if err := r.Create(ctx, configMap); err != nil {
				return "", fmt.Errorf("failed to create ConfigMap %s/%s: %w", namespace, LastResourceVersionConfigMapName, err)
			}
			return "0", nil // Start from resource version 0 after creating the ConfigMap
		}
		return "", fmt.Errorf("failed to get ConfigMap %s/%s: %w", namespace, LastResourceVersionConfigMapName, err)
	}

	resourceVersion, ok := configMap.Data[ResourceVersionKey]
	if !ok {
		// ConfigMap exists but is missing the key, initialize it
		configMap.Data[ResourceVersionKey] = "0"
		if err := r.Update(ctx, configMap); err != nil {
			return "", fmt.Errorf("failed to update ConfigMap %s/%s with initial resource version: %w", namespace, LastResourceVersionConfigMapName, err)
		}
		return "0", nil
	}

	return resourceVersion, nil
}

// updateLastResourceVersion updates the last processed resource version in the ConfigMap.
func (r *HTTPTriggerReconciler) updateLastResourceVersion(ctx context.Context, namespace string, resourceVersion string) error {
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: LastResourceVersionConfigMapName, Namespace: namespace}, configMap)
	if err != nil {
		return fmt.Errorf("failed to get ConfigMap %s/%s for update: %w", namespace, LastResourceVersionConfigMapName, err)
	}

	// Update the resource version only if it's newer
	currentRV, err := strconv.ParseInt(configMap.Data[ResourceVersionKey], 10, 64)
	if err != nil {
		currentRV = 0 // Treat invalid stored RV as 0
	}
	newRV, err := strconv.ParseInt(resourceVersion, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid new resource version format '%s': %w", resourceVersion, err)
	}

	if newRV > currentRV {
		configMap.Data[ResourceVersionKey] = resourceVersion
		if err := r.Update(ctx, configMap); err != nil {
			return fmt.Errorf("failed to update ConfigMap %s/%s: %w", namespace, LastResourceVersionConfigMapName, err)
		}
	}

	return nil
}

// UpdateTriggerStatusWithError updates the HTTPTrigger's status with a given error message.
func (r *HTTPTriggerReconciler) UpdateTriggerStatusWithError(ctx context.Context, trigger *triggersv1.HTTPTrigger, errorMessage string) {
	logger := logf.FromContext(ctx).WithValues("trigger", trigger.Name, "namespace", trigger.Namespace)
	patchedTrigger := trigger.DeepCopy()
	patchedTrigger.Status.ErrorReason = errorMessage

	if err := r.Status().Patch(ctx, patchedTrigger, client.MergeFrom(trigger)); err != nil {
		logger.Error(err, "Failed to update HTTPTrigger status with error")
	}
}

// createTrigger initializes and starts a watcher for the specified HTTPTrigger.
//nolint:gocyclo // This function has many responsibilities related to setting up the watch and HTTP client.
func (r *HTTPTriggerReconciler) createTrigger(trigger *triggersv1.HTTPTrigger) error {
	triggerRefName := trigger.Namespace + "/" + trigger.Name
	logger := logf.FromContext(r.ctx).WithValues("trigger", triggerRefName) // Use controller's context for logging setup

	// Stop any existing watcher for this trigger before starting a new one
	if cancel, ok := r.runningTriggers[triggerRefName]; ok {
		cancel()
		delete(r.runningTriggers, triggerRefName)
		logger.Info("Existing watcher stopped for trigger")
	}

	// Retrieve the last processed resource version from the ConfigMap
	lastResourceVersionFromCM, err := r.getLastResourceVersion(r.ctx, trigger.Namespace)
	if err != nil {
		logger.Error(err, "Failed to get last resource version from ConfigMap, defaulting to '0'")
		// Returning an error will cause the Reconcile loop to requeue this HTTPTrigger
		return fmt.Errorf("failed to retrieve last resource version for %s: %w", triggerRefName, err)
	}

	resourceVersion := lastResourceVersionFromCM // Use the version from ConfigMap

	logger.Info("Starting watcher", "resource", trigger.Spec.Resource.Kind, "apiVersion", trigger.Spec.Resource.APIVersion, "startResourceVersion", resourceVersion)

	listOpts := metav1.ListOptions{
		ResourceVersion:     resourceVersion,
		TimeoutSeconds:      ptr.To(int64(60)), // Watch timeout
		Watch:               true,
		AllowWatchBookmarks: false, // Set to true if bookmarks are desired and API server supports it
		LabelSelector:       strings.Join(trigger.Spec.LabelSelector, ","),
		FieldSelector:       strings.Join(trigger.Spec.FieldSelector, ","),
	}
	if trigger.Spec.SendInitialEvents {
		listOpts.SendInitialEvents = ptr.To(true)
		// Use ResourceVersionMatchNotOlderThan for resilience against resource version compaction
		listOpts.ResourceVersionMatch = metav1.ResourceVersionMatchNotOlderThan
	}

	apiParts := strings.Split(trigger.Spec.Resource.APIVersion, "/")
	if len(apiParts) == 1 {
		// Handle core API resources without a group (e.g., "v1" for Pods)
		apiParts = append(apiParts, apiParts[0])
		apiParts[0] = "" // Group is empty for core types
	}
	gvr := schema.GroupVersionResource{
		Group:    apiParts[0],
		Version:  apiParts[1],
		Resource: inflect.Pluralize(strings.ToLower(trigger.Spec.Resource.Kind)), // Convert Kind to plural resource name
	}
	gvk := schema.GroupVersionKind{
		Group:   apiParts[0],
		Version: apiParts[1],
		Kind:    trigger.Spec.Resource.Kind,
	}

	// Determine event types to trigger on
	triggerEventTypes := slices.Clone(trigger.Spec.EventType)
	if len(triggerEventTypes) == 0 {
		// Default to all event types if none are specified
		triggerEventTypes = append(triggerEventTypes,
			triggersv1.EventTypeAdded,
			triggersv1.EventTypeModified,
			triggersv1.EventTypeDeleted,
		)
	}
	eventTypes := map[string]bool{}
	for _, eventType := range triggerEventTypes {
		eventTypes[string(eventType)] = true
	}

	// Fetch dependent secrets (basic auth password, header secrets, signature key)
	depFetchCtx, depFetchCancel := context.WithTimeout(r.ctx, time.Minute)
	defer depFetchCancel()

	var userAuthPassword string
	if trigger.Spec.Auth.BasicAuth != nil {
		passwordSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.BasicAuth.PasswordRef.Name,
		}, &passwordSecret); err != nil {
			return fmt.Errorf("failed to get basic auth password secret '%s': %w", trigger.Spec.Auth.BasicAuth.PasswordRef.Name, err)
		}
		userAuthPassword = string(passwordSecret.Data[trigger.Spec.Auth.BasicAuth.PasswordRef.Key])
	}

	headerSecrets := map[string]string{}
	for k, v := range trigger.Spec.Headers.FromSecretRef {
		headerSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      v.Name,
		}, &headerSecret); err != nil {
			return fmt.Errorf("failed to get header secret '%s' for key '%s': %w", v.Name, k, err)
		}
		headerSecrets[k] = string(headerSecret.Data[v.Key])
	}

	var signature []byte
	if trigger.Spec.Body.Signature.KeySecretRef.Name != "" {
		signatureSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Body.Signature.KeySecretRef.Name,
		}, &signatureSecret); err != nil {
			return fmt.Errorf("failed to get signature key secret '%s': %w", trigger.Spec.Body.Signature.KeySecretRef.Name, err)
		}
		signature = signatureSecret.Data[trigger.Spec.Body.Signature.KeySecretRef.Key]
	}

	// Configure HTTP client transport for TLS
	httpTransport := &http.Transport{
		MaxIdleConns:    int(trigger.Spec.Concurrency),
		IdleConnTimeout: time.Minute,
	}
	if trigger.Spec.Auth.TLS != nil {
		caSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.TLS.CARef.Name,
		}, &caSecret); err != nil {
			return fmt.Errorf("failed to get TLS CA secret '%s': %w", trigger.Spec.Auth.TLS.CARef.Name, err)
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caSecret.Data[trigger.Spec.Auth.TLS.CARef.Key]); !ok {
			return fmt.Errorf("error appending CA cert to pool for secret '%s'", trigger.Spec.Auth.TLS.CARef.Name)
		}

		certSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.TLS.CertRef.Name,
		}, &certSecret); err != nil {
			return fmt.Errorf("failed to get TLS client certificate secret '%s': %w", trigger.Spec.Auth.TLS.CertRef.Name, err)
		}

		keySecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.TLS.KeyRef.Name,
		}, &keySecret); err != nil { // Assuming KeyRef exists in spec.Auth.TLS
			return fmt.Errorf("failed to get TLS client key secret '%s': %w", trigger.Spec.Auth.TLS.KeyRef.Name, err)
		}

		clientCert, err := tls.X509KeyPair(certSecret.Data[trigger.Spec.Auth.TLS.CertRef.Key], keySecret.Data[trigger.Spec.Auth.TLS.KeyRef.Key])
		if err != nil {
			return fmt.Errorf("error loading client certificate and key: %w", err)
		}

		httpTransport.TLSClientConfig = &tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{clientCert},
			InsecureSkipVerify: trigger.Spec.Auth.TLS.InsecureSkipVerify, // Use with caution!
			MinVersion:         tls.VersionTLS12,                         // Enforce TLS 1.2 or higher
		}
	}

	// Create a cancellable context for this specific watcher goroutine
	watchCtx, watchCancel := context.WithCancel(r.ctx)
	r.runningTriggers[triggerRefName] = watchCancel

	// Logger for this specific goroutine, including trigger and watched resource context
	triggerLogger := logger.WithValues("watchedGVR", gvr.String(), "namespace", trigger.Namespace)

	// Start the watcher goroutine
	go func(watchCtx context.Context, logger logr.Logger, currentTrigger *triggersv1.HTTPTrigger) {
		defer logger.Info("Watcher stopped")
		defer watchCancel() // Ensure the context is cancelled when the goroutine exits

		watcher, err := r.DynamicClient.Resource(gvr).Namespace(currentTrigger.Namespace).Watch(watchCtx, listOpts)
		if err != nil {
			logger.Error(err, "Failed to start watch", "resourceVersion", listOpts.ResourceVersion)
			// Handle specific API server errors
			if apierrors.IsResourceExpired(err) {
				logger.Info("Resource version expired, attempting to restart watch from 0 on next reconcile")
				r.UpdateTriggerStatusWithError(watchCtx, currentTrigger, fmt.Sprintf("resource version expired, watch failed: %v", err))
			} else {
				r.UpdateTriggerStatusWithError(watchCtx, currentTrigger, fmt.Sprintf("failed to start watch: %v", err))
			}
			return // Exit goroutine if watch cannot be started
		}
		defer watcher.Stop()

		httpClient := &http.Client{
			Transport: httpTransport,
			Timeout:   time.Second * time.Duration(currentTrigger.Spec.TimeoutSeconds),
		}

		for event := range watcher.ResultChan() {
			if event.Object == nil {
				continue
			}

			logger.V(1).Info("Received event", "type", event.Type, "resource", event.Object.GetObjectKind().GroupVersionKind(), "name", event.Object.GetName(), "namespace", event.Object.GetNamespace())

			// Filtering by event type
			if !eventTypes[string(event.Type)] {
				logger.V(1).Info("Event type not subscribed, skipping", "type", event.Type)
				continue
			}

			// Get the resource version from the *processed event object*
			// This is the latest resource version observed and successfully processed.
			resourceVersion := event.Object.GetResourceVersion()
			if resourceVersion == "" {
				logger.V(1).Info("Event object has no resource version, skipping update of last resource version")
				continue
			}

			// Prepare the HTTP request body
			postBody, err := r.prepareBody(logger, currentTrigger, &event, gvk)
			if err != nil {
				logger.Error(err, "Failed to prepare request body")
				r.UpdateTriggerStatusWithError(watchCtx, currentTrigger, fmt.Sprintf("failed to prepare request body: %v", err))
				continue // Skip sending HTTP request if body preparation failed
			}

			// Create and configure HTTP request
			req, err := http.NewRequestWithContext(watchCtx, http.MethodPost, currentTrigger.Spec.URL, bytes.NewBuffer(postBody))
			if err != nil {
				logger.Error(err, "Failed to create HTTP request")
				r.UpdateTriggerStatusWithError(watchCtx, currentTrigger, fmt.Sprintf("failed to create http request: %v", err))
				continue
			}

			r.prepareHeaders(req, currentTrigger, userAuthPassword, headerSecrets, signature, postBody)

			// Send HTTP request
			resp, err := httpClient.Do(req)
			if err != nil {
				logger.Error(err, "HTTP request failed")
				r.UpdateTriggerStatusWithError(watchCtx, currentTrigger, fmt.Sprintf("http request failed: %v", err))
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				respBody := new(bytes.Buffer)
				_, _ = respBody.ReadFrom(resp.Body)
				err = fmt.Errorf("received non-success status code: %d, body: %s", resp.StatusCode, respBody.String())
				logger.Error(err, "HTTP request failed with non-2xx status")
				r.UpdateTriggerStatusWithError(watchCtx, currentTrigger, fmt.Sprintf("http request returned non-2xx status: %d", resp.StatusCode))
				continue
			}

			logger.V(1).Info("HTTP request successful", "status", resp.Status)

			// After successfully processing an event, update the ConfigMap with the latest resource version.
			// This ensures that if the controller restarts, it can resume from this point.
			if err := r.updateLastResourceVersion(watchCtx, currentTrigger.Namespace, resourceVersion); err != nil {
				logger.Error(err, "Failed to update last resource version in ConfigMap")
				// This is a non-fatal error for the watcher, but important to log.
				// The watcher continues, but restart recovery might be impacted.
			}
		}
	}(watchCtx, triggerLogger, trigger.DeepCopy()) // Pass logger and a deep copy of the trigger to the goroutine

	return nil
}

// prepareBody constructs the HTTP request body based on the trigger's specification.
func (r *HTTPTriggerReconciler) prepareBody(logger logr.Logger, trigger *triggersv1.HTTPTrigger, event *watch.Event, gvk schema.GroupVersionKind) ([]byte, error) {
	var postBody []byte

	// Prepare data for templating, including event type and object details
	templateData := map[string]interface{}{
		"Type": event.Type,
		"Object": map[string]interface{}{
			"Kind":            gvk.Kind,
			"APIVersion":      gvk.GroupVersion().String(),
			"Name":            event.Object.GetName(),
			"Namespace":       event.Object.GetNamespace(),
			"Labels":          event.Object.GetLabels(),
			"Annotations":     event.Object.GetAnnotations(),
			"ResourceVersion": event.Object.GetResourceVersion(),
			// Include the full unstructured object for advanced templating
			"FullObject": event.Object.UnstructuredContent(),
		},
		"Now": time.Now().Format(time.RFC3339), // Add current timestamp
	}

	if trigger.Spec.Body.Template != "" {
		tmpl, err := template.New("body").Parse(trigger.Spec.Body.Template)
		if err != nil {
			return nil, fmt.Errorf("failed to parse body template: %w", err)
		}
		var bodyBuf bytes.Buffer
		if err := tmpl.Execute(&bodyBuf, templateData); err != nil {
			return nil, fmt.Errorf("failed to execute body template: %w", err)
		}
		postBody = bodyBuf.Bytes()
	} else if trigger.Spec.Body.ForwardObject {
		// If ForwardObject is true, send the raw unstructured object as JSON
		var err error
		postBody, err = json.Marshal(event.Object.UnstructuredContent())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal object for forwarding: %w", err)
		}
	} else {
		// Default: send a minimal JSON payload
		var err error
		postBody, err = json.Marshal(templateData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal default body: %w", err)
		}
	}

	return postBody, nil
}

// prepareHeaders sets the necessary HTTP headers for the request.
func (r *HTTPTriggerReconciler) prepareHeaders(req *http.Request, trigger *triggersv1.HTTPTrigger, userAuthPassword string, headerSecrets map[string]string, signature []byte, postBody []byte) {
	// Set default Content-Type if not provided
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add custom headers from spec
	for k, v := range trigger.Spec.Headers.Static {
		req.Header.Set(k, v)
	}
	for k, v := range headerSecrets {
		req.Header.Set(k, v)
	}

	// Add Basic Authentication header if configured
	if trigger.Spec.Auth.BasicAuth != nil {
		req.SetBasicAuth(trigger.Spec.Auth.BasicAuth.Username, userAuthPassword)
	}

	// Add HMAC signature if configured
	if trigger.Spec.Body.Signature.KeySecretRef.Name != "" && len(signature) > 0 {
		var h hash.Hash
		switch trigger.Spec.Body.Signature.Algorithm {
		case "sha256":
			h = hmac.New(sha256.New, signature)
		case "sha512":
			h = hmac.New(sha512.New, signature)
		default:
			h = hmac.New(sha256.New, signature) // Default to sha256
		}
		h.Write(postBody)
		req.Header.Set(trigger.Spec.Body.Signature.HeaderName, hex.EncodeToString(h.Sum(nil)))
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPTriggerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.ctx = context.Background() // Initialize the main controller context
	r.runningTriggers = map[string]func(){}
	r.DynamicClient = dynamic.New(mgr.GetConfig()) // Initialize dynamic client

	// Add a Watcher to the manager that will call the Reconciler's Start method.
	// Note: The Watcher's Start method is currently empty as per the existing code.
	// The actual watches are initiated per HTTPTrigger in the Reconcile loop.
	// If a global watch mechanism is intended, the Watcher.Start logic needs implementation.
	if err := mgr.Add(&Watcher{Reconciler: r}); err != nil {
		return fmt.Errorf("failed to add watcher to manager: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&triggersv1.HTTPTrigger{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 10, // Concurrency for HTTPTrigger reconciles
		}).
		Complete(r)
}