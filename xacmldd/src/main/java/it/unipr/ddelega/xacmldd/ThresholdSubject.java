package it.unipr.ddelega.xacmldd;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ThresholdSubject {

	/** N / N Threshold Subject type (Intersection). */
	public static final int N_OVER_N = 0;

	/** 1 / N Threshold Subject type (Union). */
	public static final int ONE_OVER_N = 1;

	/** List of subjects of this threshold */
	List<String> subjects;

	/** Threshold type */
	int thType;

	/** Defualt constructor. The default threshold type is {@link #N_OVER_N} */
	public ThresholdSubject() {
		subjects = new ArrayList<String>();
		thType = N_OVER_N;
	}

	/** 
	 * Builds the threshold subject specifing the type (intersection or union).
	 * 
	 * @param type the type of threshold (<code>N_OVER_N</code> or <code>ONE_OVER_N</code>)
	 */
	public ThresholdSubject(int type) {
		subjects = new ArrayList<String>();
		thType = type; 
	}

	/**
	 * Builds the threshold subject specifing the type and adding the subjects contained in the given list. 
	 *
	 * @param subjectList the list of subjects to add to the threshold subject
	 * @param type the type of threshold (<code>N_OVER_N</code> or <code>ONE_OVER_N</code>)
	 */
	public ThresholdSubject(List<String> subjectList, int type) {
		subjects = new ArrayList<String>();		
		subjects.addAll(subjectList);
		thType = type;
	}

	/** 
	 * Sets the threshold type. The type can be <code>N_OVER_N</code> or <ONE_OVER_N>. The
	 * former specifies an intersection, the latter an union.
	 * 
	 * @param type the new type of threshold
	 */ 
	public void setThresholdType(int type) {
		thType = type;
	}

	/**
	 * Gets the threshold type.
	 * 
	 * @return the type of threshold of this subject. <code>N_OVER_N</code>, <code>ONE_OVER_N</code> or -1 if the type is still unspecified.
	 */
	public int getThresholdType() {
		return thType;
	}

	/**
	 * Gets the <i>immutable</i> list of certificates contained in this threshold.
	 * 
	 * @return the list of certificates. The list is immutable.
	 */
	public List<String> getSubjects() {
		return Collections.unmodifiableList(subjects);
	}

	/**
	 * Adds the given subject to the threshold. The subject must be a local name.
	 * 
	 * @param qualifier the namespace qualifier of the name.
	 * @param localName the name local to the namespace.
	 */
	public void addSubject(String qualifier, String localName) {
		subjects.add(XacmlddHelper.createFullyQualifiedName(qualifier, localName));
	}

	/**
	 * Removes the given subject from the threshold, if present. The subject must be a local name.  
	 * 
	 * @param qualifier the namespace qualfier of the name.
	 * @param localName the local name.
	 * @return <code>true</code> if the removal is succesful, <code>false</code> if the subject is not present.
	 */
	public boolean removeSubject(String qualifier, String localName) {
		return subjects.remove(XacmlddHelper.createFullyQualifiedName(qualifier, localName));
	}

	/** 
	 * Adds the given subject to the threshold. The string must be a key hash made using {@link XacmlddHelper}.
	 * 
	 * @param keyHash the hash of the key that rapresent the subject.
	 */
	public void addSubject(String keyHash) {
		if (XacmlddHelper.isKeyHash(keyHash)) {
			subjects.add(keyHash);
		}
	}

	/** 
	 * Removes the given subject from the threshold, if present. The subject must be a key hash obtained from {@link XacmlddHelper}. 
	 * 
	 * @param keyHash the hash of the key to be removed from the threshold.
	 * @return <code>true</code> if the subject was removed, <code>false</code> otherwise.
	 */
	public boolean removeSubject(String keyHash) {
		return subjects.remove(keyHash);
	}

	/** Removes all subject from the threshold. This operation <b>will not</b> change the threshold type. */
	public void clear() {
		subjects.clear();
	}

	/**
	 * Returns the numeber of subjects in this threshold subject.
	 * 
	 * @return the number of subjects.
	 */
	public int size() {
		return subjects.size();
	}

	/** {@inheritDoc} */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ThresholdSubject)) {
			return false;			
		}

		ThresholdSubject sbj = (ThresholdSubject) obj; 
		if (this.size() == sbj.size() && sbj.thType == this.thType) {
			int max = this.size();
			for(int i = 0; i < max; i++) {
				if (!this.subjects.get(i).equals(sbj.subjects.get(i))) {
					return false;
				}
			}

			return true;
		}

		return false;			
	}
}
