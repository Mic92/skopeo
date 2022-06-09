package nix

import(
	"context"
	"fmt"
	"io"
	"encoding/json"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
	"github.com/pkg/errors"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/image"
	digest "github.com/opencontainers/go-digest"
	"github.com/nlewo/nix2container/nix"
	nixtypes "github.com/nlewo/nix2container/types"
)

func init() {
	transports.Register(Transport)
}

// Transport is an ImageTransport for local Docker archives.
var Transport = nixTransport{}

type nixTransport struct{}

func (t nixTransport) Name() string {
	return "nix"
}

type nixReference struct {
	path string
	nixImage nixtypes.Image
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix, into an ImageReference.
func (t nixTransport) ParseReference(reference string) (types.ImageReference, error) {
	nixImage, err := nix.NewImageFromFile(reference)
	if err != nil {
		return nil, err
	}
	imageReference := nixReference{
		path: reference,
		nixImage: nixImage,
	}
	return imageReference, nil
}

// ValidatePolicyConfigurationScope checks that scope is a valid name for a signature.PolicyTransportScopes keys
// (i.e. a valid PolicyConfigurationIdentity() or PolicyConfigurationNamespaces() return value).
// It is acceptable to allow an invalid value which will never be matched, it can "only" cause user confusion.
// scope passed to this function will not be "", that value is always allowed.
func (t nixTransport) ValidatePolicyConfigurationScope(scope string) error {
	// See the explanation in archiveReference.PolicyConfigurationIdentity.
	return errors.New(`nix: does not support any scopes except the default "" one`)
}

// StringWithinTransport returns a string representation of the reference, which MUST be such that
// reference.Transport().ParseReference(reference.StringWithinTransport()) returns an equivalent reference.
func (ref nixReference) StringWithinTransport() string {
	return fmt.Sprintf("%s", ref.path)
}

func (ref nixReference) Transport() types.ImageTransport {
	return Transport
}

// DeleteImage deletes the named image from the registry, if supported.
func (ref nixReference) DeleteImage(ctx context.Context, sys *types.SystemContext) error {
	// Not really supported, for safety reasons.
	return errors.New("Deleting images not implemented for docker-archive: images")
}

// DockerReference returns a Docker reference associated with this reference
// (fully explicit, i.e. !reference.IsNameOnly, but reflecting user intent,
// not e.g. after redirect or alias processing), or nil if unknown/not applicable.
func (ref nixReference) DockerReference() reference.Named {
	return nil
}

// NewImage returns a types.ImageCloser for this reference, possibly specialized for this ImageTransport.
// The caller must call .Close() on the returned ImageCloser.
// NOTE: If any kind of signature verification should happen, build an UnparsedImage from the value returned by NewImageSource,
// verify that UnparsedImage, and convert it into a real Image via image.FromUnparsedImage.
// WARNING: This may not do the right thing for a manifest list, see image.FromSource for details.
func (ref nixReference) NewImage(ctx context.Context, sys *types.SystemContext) (types.ImageCloser, error) {
	src, err := newImageSource(ctx, sys, ref)
	if err != nil {
		return nil, err
	}
	return image.FromSource(ctx, sys, src)
}

// NewImageSource returns a types.ImageSource for this reference.
// The caller must call .Close() on the returned ImageSource.
func (ref nixReference) NewImageSource(ctx context.Context, sys *types.SystemContext) (types.ImageSource, error) {
	return newImageSource(ctx, sys, ref)
}

// PolicyConfigurationIdentity returns a string representation of the reference, suitable for policy lookup.
func (ref nixReference) PolicyConfigurationIdentity() string {
	return ""
}

// PolicyConfigurationNamespaces returns a list of other policy configuration namespaces to search
// for if explicit configuration for PolicyConfigurationIdentity() is not set
func (ref nixReference) PolicyConfigurationNamespaces() []string {
	return []string{}
}

// NewImageDestination returns a types.ImageDestination for this reference.
// The caller must call .Close() on the returned ImageDestination.
func (ref nixReference) NewImageDestination(ctx context.Context, sys *types.SystemContext) (types.ImageDestination, error) {
	return nil, errors.New("NewImageDestination is not implemented for nix: images")
}

// newImageSource returns an ImageSource for reading from an existing directory.
// newImageSource untars the file and saves it in a temp directory
func newImageSource(ctx context.Context, sys *types.SystemContext, ref nixReference) (types.ImageSource, error) {
	return &nixImageSource{
		ref: ref,
	}, nil
}

type nixImageSource struct {
	ref         nixReference
}

// Close removes resources associated with an initialized ImageSource, if any.
// Close deletes the temporary directory at dst
func (s *nixImageSource) Close() error {
	return nil
}

func (s *nixImageSource) GetBlob(ctx context.Context, info types.BlobInfo, cache types.BlobInfoCache) (io.ReadCloser, int64, error) {
	// TODO: returning the blob size here leads to the following error on image copy:
	// FATA[0000] writing blob: archive/tar: write too long
	rc, _, err := nix.GetBlob(s.ref.nixImage, info.Digest)
	return rc, -1, err
}

// GetManifest returns the image's manifest along with its MIME type (which may be empty when it can't be determined but the manifest is available).
// It may use a remote (= slow) service.
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to retrieve (when the primary manifest is a manifest list);
// this never happens if the primary manifest is not a manifest list (e.g. if the source never returns manifest lists).
func (s *nixImageSource) GetManifest(ctx context.Context, instanceDigest *digest.Digest) ([]byte, string, error) {
	configDigest, size, err := nix.GetConfigDigest(s.ref.nixImage)
	if err != nil {
		return nil, "", err
	}
	config := imgspecv1.Descriptor{
		MediaType: imgspecv1.MediaTypeImageConfig,
		Size:      size,
		Digest:    configDigest,
	}

	var layers []imgspecv1.Descriptor
	for _, layer := range(s.ref.nixImage.Layers)	{
		digest, err := digest.Parse(layer.Digest)
		if err != nil {
			return nil, "", err
		}
		layers = append(layers, imgspecv1.Descriptor{
			MediaType: layer.MediaType,
			Size:      layer.Size,
			Digest:    digest,
		})
	}

        m := manifest.OCI1FromComponents(
		config,
		layers,
	)
	manifestBytes, err := json.Marshal(&m)
	if err != nil {
		return nil, "", err
	}
	return manifestBytes, imgspecv1.MediaTypeImageManifest, nil
}

func (s *nixImageSource) GetSignatures(ctx context.Context, instanceDigest *digest.Digest) ([][]byte, error) {
	return [][]byte{}, nil
}

// HasThreadSafeGetBlob indicates whether GetBlob can be executed concurrently.
func (s *nixImageSource) HasThreadSafeGetBlob() bool {
	return false
}

// LayerInfosForCopy returns either nil (meaning the values in the manifest are fine), or updated values for the layer
// blobsums that are listed in the image's manifest.  If values are returned, they should be used when using GetBlob()
// to read the image's layers.
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to retrieve BlobInfos for
// (when the primary manifest is a manifest list); this never happens if the primary manifest is not a manifest list
// (e.g. if the source never returns manifest lists).
// The Digest field is guaranteed to be provided; Size may be -1.
// WARNING: The list may contain duplicates, and they are semantically relevant.
func (s *nixImageSource) LayerInfosForCopy(ctx context.Context, instanceDigest *digest.Digest) ([]types.BlobInfo, error) {
	return nil, nil
}

// Reference returns the reference used to set up this source.
func (s *nixImageSource) Reference() types.ImageReference {
	return s.ref
}
